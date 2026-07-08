//! Dependency resolution and installation (WS9-02.5).
//!
//! A [`PackageIndex`] is the set of manifests available to install. [`resolve`]
//! walks a target's dependency graph and returns the manifests in install order
//! (dependencies before dependents), reporting missing dependencies,
//! unsatisfiable version requirements, version conflicts, and cycles. The
//! [`Installer`] drives an install: it resolves, checks each package's content
//! is present in a [`ContentStore`], and records the [`InstalledPackage`] set.
//!
//! This is the resolution + local-install engine. Fetching package content over
//! the network is the capability-bound fetch (WS9-02.10); atomic version
//! transitions are upgrade/rollback (WS9-02.6/.7); signature/CT-log checks are
//! WS9-02.3/.4.
//!
//! [`resolve`]: PackageIndex::resolve

use std::collections::HashMap;

use crate::{
    manifest::{PackageManifest, PackageName, Version},
    store::ContentStore,
};

/// Why dependency resolution failed (WS9-02.5).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// A required package is not in the index at all.
    #[error("missing dependency: {0}")]
    Missing(PackageName),
    /// The package exists but no available version meets the requirement.
    #[error("no version of {name} satisfies >= {required}")]
    Unsatisfiable {
        /// The package whose versions were all too old.
        name: PackageName,
        /// The minimum version that was required.
        required: Version,
    },
    /// Two requirements on the same package cannot be met by one chosen version.
    #[error("version conflict on {name}: chose {have} but >= {need} is also required")]
    Conflict {
        /// The package with conflicting requirements.
        name: PackageName,
        /// The version already chosen earlier in the walk.
        have: Version,
        /// A later, stricter requirement the chosen version fails.
        need: Version,
    },
    /// The dependency graph contains a cycle through this package.
    #[error("dependency cycle through {0}")]
    Cycle(PackageName),
}

/// Per-package resolution state during the graph walk.
#[derive(Debug, Clone, Copy)]
enum Mark {
    /// On the current DFS stack (a back-edge to it is a cycle).
    Visiting,
    /// Fully resolved at the given chosen version.
    Done(Version),
}

/// The set of package manifests available to install (WS9-02.5).
#[derive(Debug, Clone, Default)]
pub struct PackageIndex {
    by_name: HashMap<PackageName, Vec<PackageManifest>>,
}

impl PackageIndex {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an available manifest (multiple versions of one package may coexist).
    pub fn add(&mut self, manifest: PackageManifest) {
        self.by_name
            .entry(manifest.name.clone())
            .or_default()
            .push(manifest);
    }

    /// The highest available version of `name` that is at least `min_version`.
    #[must_use]
    pub fn best(&self, name: &PackageName, min_version: Version) -> Option<&PackageManifest> {
        self.by_name
            .get(name)?
            .iter()
            .filter(|m| m.version >= min_version)
            .max_by_key(|m| m.version)
    }

    /// The number of distinct package names indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Resolve `name` (>= `min_version`) and all its transitive dependencies
    /// into install order — each package after every package it depends on.
    ///
    /// # Errors
    ///
    /// Returns a [`ResolveError`] for a missing dependency, an unsatisfiable
    /// version requirement, a version conflict, or a dependency cycle.
    pub fn resolve(
        &self,
        name: &PackageName,
        min_version: Version,
    ) -> Result<Vec<PackageManifest>, ResolveError> {
        let mut marks: HashMap<PackageName, Mark> = HashMap::new();
        let mut order = Vec::new();
        self.visit(name, min_version, &mut marks, &mut order)?;
        Ok(order)
    }

    fn visit(
        &self,
        name: &PackageName,
        min_version: Version,
        marks: &mut HashMap<PackageName, Mark>,
        order: &mut Vec<PackageManifest>,
    ) -> Result<(), ResolveError> {
        match marks.get(name) {
            Some(Mark::Done(chosen)) => {
                return if *chosen >= min_version {
                    Ok(())
                } else {
                    Err(ResolveError::Conflict {
                        name: name.clone(),
                        have: *chosen,
                        need: min_version,
                    })
                };
            }
            Some(Mark::Visiting) => return Err(ResolveError::Cycle(name.clone())),
            None => {}
        }

        let versions = self
            .by_name
            .get(name)
            .ok_or_else(|| ResolveError::Missing(name.clone()))?;
        let manifest = versions
            .iter()
            .filter(|m| m.version >= min_version)
            .max_by_key(|m| m.version)
            .ok_or_else(|| ResolveError::Unsatisfiable {
                name: name.clone(),
                required: min_version,
            })?
            .clone();

        marks.insert(name.clone(), Mark::Visiting);
        for dep in &manifest.dependencies {
            self.visit(&dep.name, dep.min_version, marks, order)?;
        }
        marks.insert(name.clone(), Mark::Done(manifest.version));
        order.push(manifest);
        Ok(())
    }
}

/// A record of an installed package (WS9-02.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstalledPackage {
    /// The installed version.
    pub version: Version,
    /// The content address of the installed artifact.
    pub address: [u8; crate::manifest::CONTENT_HASH_LEN],
}

/// Why an install failed (WS9-02.5).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstallError {
    /// Dependency resolution failed.
    #[error("resolution failed: {0}")]
    Resolve(#[from] ResolveError),
    /// A resolved package's content is not present in the store (it must be
    /// fetched first — WS9-02.10).
    #[error("content for {0} is not in the store")]
    ContentMissing(PackageName),
}

/// Why an atomic upgrade failed (WS9-02.6).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpgradeError {
    /// The package is not installed, so there is nothing to upgrade.
    #[error("{0} is not installed")]
    NotInstalled(PackageName),
    /// No available version is newer than the installed one.
    #[error("{name} is already at the newest available version {current}")]
    NothingToUpgrade {
        /// The package considered for upgrade.
        name: PackageName,
        /// The currently installed version.
        current: Version,
    },
    /// The new version's dependency closure could not be resolved.
    #[error("resolution failed: {0}")]
    Resolve(#[from] ResolveError),
    /// A package in the new closure has no content in the store.
    #[error("content for {0} is not in the store")]
    ContentMissing(PackageName),
}

/// Why a rollback failed (WS9-02.7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RollbackError {
    /// There is no previous version recorded to roll back to.
    #[error("no previous version of {0} to roll back to")]
    NoPreviousVersion(PackageName),
}

/// Tracks installed packages and drives dependency-resolving installs
/// (WS9-02.5) plus atomic upgrade/rollback (WS9-02.6/.7).
///
/// For each package the installer keeps the current [`InstalledPackage`] and,
/// once it has been upgraded at least once, the immediately previous record so
/// a single rollback can restore it.
#[derive(Debug, Clone, Default)]
pub struct Installer {
    installed: HashMap<PackageName, InstalledPackage>,
    previous: HashMap<PackageName, InstalledPackage>,
}

impl Installer {
    /// An installer with nothing installed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve and install `name` (>= `min_version`) from `index`, requiring
    /// each resolved package's content to be present in `store`. Installs in
    /// dependency order and records every package. Returns the install order.
    ///
    /// Content presence is checked for the whole set *before* anything is
    /// recorded, so a failed install leaves the installed set unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`InstallError::Resolve`] if dependencies cannot be resolved, or
    /// [`InstallError::ContentMissing`] if a resolved package's artifact is not
    /// in the store.
    pub fn install(
        &mut self,
        index: &PackageIndex,
        store: &ContentStore,
        name: &PackageName,
        min_version: Version,
    ) -> Result<Vec<PackageName>, InstallError> {
        let order = index.resolve(name, min_version)?;
        // Verify all content is present before mutating any state.
        for manifest in &order {
            if !store.contains(&manifest.content_hash) {
                return Err(InstallError::ContentMissing(manifest.name.clone()));
            }
        }
        let mut installed_order = Vec::with_capacity(order.len());
        for manifest in order {
            self.installed.insert(
                manifest.name.clone(),
                InstalledPackage {
                    version: manifest.version,
                    address: manifest.content_hash,
                },
            );
            installed_order.push(manifest.name);
        }
        Ok(installed_order)
    }

    /// Atomically upgrade an installed package to the newest available version
    /// that is at least `min_version` (WS9-02.6).
    ///
    /// Resolves the new version's full dependency closure and verifies every
    /// package's content is present *before* changing any state, then applies
    /// the new records and snapshots the package's prior record for
    /// [`rollback`](Installer::rollback). Returns the new record for `name`.
    ///
    /// # Errors
    ///
    /// Returns [`UpgradeError::NotInstalled`] if `name` is not installed,
    /// [`UpgradeError::NothingToUpgrade`] if no newer version exists,
    /// [`UpgradeError::Resolve`] if the new closure cannot be resolved, or
    /// [`UpgradeError::ContentMissing`] if any package's content is absent.
    pub fn upgrade(
        &mut self,
        index: &PackageIndex,
        store: &ContentStore,
        name: &PackageName,
        min_version: Version,
    ) -> Result<InstalledPackage, UpgradeError> {
        let current = self
            .installed
            .get(name)
            .ok_or_else(|| UpgradeError::NotInstalled(name.clone()))?
            .version;
        let target = index
            .best(name, min_version)
            .ok_or_else(|| UpgradeError::NothingToUpgrade {
                name: name.clone(),
                current,
            })?
            .version;
        if target <= current {
            return Err(UpgradeError::NothingToUpgrade {
                name: name.clone(),
                current,
            });
        }
        let closure = index.resolve(name, target)?;
        // Atomicity pre-check: every package's content must be present.
        for manifest in &closure {
            if !store.contains(&manifest.content_hash) {
                return Err(UpgradeError::ContentMissing(manifest.name.clone()));
            }
        }
        // Snapshot the package's prior record, then apply the new closure.
        if let Some(prev) = self.installed.get(name).copied() {
            self.previous.insert(name.clone(), prev);
        }
        for manifest in closure {
            self.installed.insert(
                manifest.name.clone(),
                InstalledPackage {
                    version: manifest.version,
                    address: manifest.content_hash,
                },
            );
        }
        self.installed
            .get(name)
            .copied()
            .ok_or_else(|| UpgradeError::NotInstalled(name.clone()))
    }

    /// Roll a package back to its previous version (WS9-02.7).
    ///
    /// Restores the record snapshotted by the last [`upgrade`](Installer::upgrade)
    /// and consumes it (a second consecutive rollback fails). Returns the
    /// restored record.
    ///
    /// # Errors
    ///
    /// Returns [`RollbackError::NoPreviousVersion`] if no prior record exists.
    pub fn rollback(&mut self, name: &PackageName) -> Result<InstalledPackage, RollbackError> {
        let prior = self
            .previous
            .remove(name)
            .ok_or_else(|| RollbackError::NoPreviousVersion(name.clone()))?;
        self.installed.insert(name.clone(), prior);
        Ok(prior)
    }

    /// The previous (rollback target) record for `name`, if any.
    #[must_use]
    pub fn previous(&self, name: &PackageName) -> Option<&InstalledPackage> {
        self.previous.get(name)
    }

    /// The record for `name`, if installed.
    #[must_use]
    pub fn installed(&self, name: &PackageName) -> Option<&InstalledPackage> {
        self.installed.get(name)
    }

    /// Whether `name` is installed.
    #[must_use]
    pub fn is_installed(&self, name: &PackageName) -> bool {
        self.installed.contains_key(name)
    }

    /// The number of installed packages.
    #[must_use]
    pub fn count(&self) -> usize {
        self.installed.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::manifest::Dependency;

    fn pn(s: &str) -> PackageName {
        PackageName::new(s).expect("valid name")
    }

    fn v(a: u32, b: u32, c: u32) -> Version {
        Version::new(a, b, c)
    }

    /// A manifest with the given name, version, content hash tag, and deps.
    fn manifest(name: &str, ver: Version, tag: u8, deps: &[(&str, Version)]) -> PackageManifest {
        let mut m = PackageManifest::new(pn(name), ver, [tag; crate::manifest::CONTENT_HASH_LEN]);
        for (dn, dv) in deps {
            m.dependencies.push(Dependency::new(pn(dn), *dv));
        }
        m
    }

    fn chain_index() -> PackageIndex {
        let mut index = PackageIndex::new();
        index.add(manifest("base", v(1, 0, 0), 1, &[]));
        index.add(manifest("lib", v(1, 0, 0), 2, &[("base", v(1, 0, 0))]));
        index.add(manifest("app", v(1, 0, 0), 3, &[("lib", v(1, 0, 0))]));
        index
    }

    #[test]
    fn resolve_orders_dependencies_first() {
        let index = chain_index();
        let order = index.resolve(&pn("app"), v(1, 0, 0)).expect("resolves");
        let names: Vec<&str> = order.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["base", "lib", "app"]);
    }

    #[test]
    fn best_picks_highest_satisfying_version() {
        let mut index = PackageIndex::new();
        index.add(manifest("lib", v(1, 0, 0), 1, &[]));
        index.add(manifest("lib", v(1, 4, 0), 2, &[]));
        index.add(manifest("lib", v(2, 0, 0), 3, &[]));
        assert_eq!(
            index.best(&pn("lib"), v(1, 0, 0)).map(|m| m.version),
            Some(v(2, 0, 0))
        );
        assert_eq!(
            index.best(&pn("lib"), v(1, 1, 0)).map(|m| m.version),
            Some(v(2, 0, 0))
        );
        assert_eq!(index.best(&pn("lib"), v(3, 0, 0)), None);
    }

    #[test]
    fn resolve_reports_missing_dependency() {
        let mut index = PackageIndex::new();
        index.add(manifest("app", v(1, 0, 0), 1, &[("ghost", v(1, 0, 0))]));
        assert_eq!(
            index.resolve(&pn("app"), v(1, 0, 0)),
            Err(ResolveError::Missing(pn("ghost")))
        );
    }

    #[test]
    fn resolve_reports_unsatisfiable_version() {
        let mut index = PackageIndex::new();
        index.add(manifest("lib", v(1, 0, 0), 1, &[]));
        index.add(manifest("app", v(1, 0, 0), 2, &[("lib", v(2, 0, 0))]));
        assert_eq!(
            index.resolve(&pn("app"), v(1, 0, 0)),
            Err(ResolveError::Unsatisfiable {
                name: pn("lib"),
                required: v(2, 0, 0),
            })
        );
    }

    #[test]
    fn resolve_reports_version_conflict() {
        // app needs lib>=1.0 and dep needs lib>=2.0, but only lib 1.0 exists,
        // and they get chosen in an order that surfaces the conflict.
        let mut index = PackageIndex::new();
        index.add(manifest("lib", v(1, 0, 0), 1, &[]));
        index.add(manifest("mid", v(1, 0, 0), 2, &[("lib", v(2, 0, 0))]));
        index.add(manifest(
            "app",
            v(1, 0, 0),
            3,
            &[("lib", v(1, 0, 0)), ("mid", v(1, 0, 0))],
        ));
        // lib is chosen at 1.0.0 (for app), then mid requires lib>=2.0.0.
        assert_eq!(
            index.resolve(&pn("app"), v(1, 0, 0)),
            Err(ResolveError::Conflict {
                name: pn("lib"),
                have: v(1, 0, 0),
                need: v(2, 0, 0),
            })
        );
    }

    #[test]
    fn resolve_detects_cycles() {
        let mut index = PackageIndex::new();
        index.add(manifest("a", v(1, 0, 0), 1, &[("b", v(1, 0, 0))]));
        index.add(manifest("b", v(1, 0, 0), 2, &[("a", v(1, 0, 0))]));
        assert!(matches!(
            index.resolve(&pn("a"), v(1, 0, 0)),
            Err(ResolveError::Cycle(_))
        ));
    }

    #[test]
    fn resolve_handles_diamonds_without_duplicates() {
        let mut index = PackageIndex::new();
        index.add(manifest("base", v(1, 0, 0), 1, &[]));
        index.add(manifest("left", v(1, 0, 0), 2, &[("base", v(1, 0, 0))]));
        index.add(manifest("right", v(1, 0, 0), 3, &[("base", v(1, 0, 0))]));
        index.add(manifest(
            "top",
            v(1, 0, 0),
            4,
            &[("left", v(1, 0, 0)), ("right", v(1, 0, 0))],
        ));
        let order = index.resolve(&pn("top"), v(1, 0, 0)).expect("resolves");
        let names: Vec<&str> = order.iter().map(|m| m.name.as_str()).collect();
        // base appears once and before both left and right; top last.
        assert_eq!(names.iter().filter(|n| **n == "base").count(), 1);
        assert_eq!(names.first(), Some(&"base"));
        assert_eq!(names.last(), Some(&"top"));
    }

    #[test]
    fn install_records_packages_when_content_present() {
        let mut store = ContentStore::new();
        // Each manifest's content_hash must match what's in the store.
        let mut index = PackageIndex::new();
        for (name, tag, deps) in [
            ("base", b"base".as_slice(), Vec::new()),
            ("lib", b"lib".as_slice(), vec![("base", v(1, 0, 0))]),
            ("app", b"app".as_slice(), vec![("lib", v(1, 0, 0))]),
        ] {
            let addr = store.put(tag.to_vec());
            let mut m = PackageManifest::new(pn(name), v(1, 0, 0), addr);
            for (dn, dv) in deps {
                m.dependencies.push(Dependency::new(pn(dn), dv));
            }
            index.add(m);
        }
        let mut installer = Installer::new();
        let order = installer
            .install(&index, &store, &pn("app"), v(1, 0, 0))
            .expect("installs");
        assert_eq!(
            order.iter().map(PackageName::as_str).collect::<Vec<_>>(),
            vec!["base", "lib", "app"]
        );
        assert!(installer.is_installed(&pn("app")));
        assert_eq!(installer.count(), 3);
        assert_eq!(
            installer.installed(&pn("lib")).map(|p| p.version),
            Some(v(1, 0, 0))
        );
    }

    #[test]
    fn install_fails_and_records_nothing_when_content_missing() {
        // Index has the manifest but the store does not have its content.
        let mut index = PackageIndex::new();
        index.add(manifest("app", v(1, 0, 0), 9, &[]));
        let store = ContentStore::new();
        let mut installer = Installer::new();
        assert_eq!(
            installer.install(&index, &store, &pn("app"), v(1, 0, 0)),
            Err(InstallError::ContentMissing(pn("app")))
        );
        assert_eq!(installer.count(), 0);
    }

    // --- Atomic upgrade / rollback (WS9-02.6 / .7) --------------------------

    /// Add a versioned package with its content to both the store and index.
    fn add_pkg(
        store: &mut ContentStore,
        index: &mut PackageIndex,
        name: &str,
        ver: Version,
        content: &[u8],
    ) {
        let addr = store.put(content.to_vec());
        index.add(PackageManifest::new(pn(name), ver, addr));
    }

    #[test]
    fn upgrade_moves_to_newer_version_and_rollback_restores() {
        let mut store = ContentStore::new();
        let mut index = PackageIndex::new();
        add_pkg(&mut store, &mut index, "app", v(1, 0, 0), b"app-1.0.0");
        let mut inst = Installer::new();
        // Only 1.0.0 is available at install time, so 1.0.0 is what gets installed.
        inst.install(&index, &store, &pn("app"), v(1, 0, 0))
            .expect("install");
        assert_eq!(
            inst.installed(&pn("app")).map(|p| p.version),
            Some(v(1, 0, 0))
        );

        // A newer version is then published.
        add_pkg(&mut store, &mut index, "app", v(1, 1, 0), b"app-1.1.0");
        let upgraded = inst
            .upgrade(&index, &store, &pn("app"), v(1, 0, 0))
            .expect("upgrade");
        assert_eq!(upgraded.version, v(1, 1, 0));
        assert_eq!(
            inst.installed(&pn("app")).map(|p| p.version),
            Some(v(1, 1, 0))
        );
        assert_eq!(
            inst.previous(&pn("app")).map(|p| p.version),
            Some(v(1, 0, 0))
        );

        let restored = inst.rollback(&pn("app")).expect("rollback");
        assert_eq!(restored.version, v(1, 0, 0));
        assert_eq!(
            inst.installed(&pn("app")).map(|p| p.version),
            Some(v(1, 0, 0))
        );
        assert!(inst.previous(&pn("app")).is_none());
    }

    #[test]
    fn upgrade_requires_the_package_be_installed() {
        let store = ContentStore::new();
        let index = PackageIndex::new();
        let mut inst = Installer::new();
        assert_eq!(
            inst.upgrade(&index, &store, &pn("app"), v(1, 0, 0)),
            Err(UpgradeError::NotInstalled(pn("app")))
        );
    }

    #[test]
    fn upgrade_reports_nothing_when_already_newest() {
        let mut store = ContentStore::new();
        let mut index = PackageIndex::new();
        add_pkg(&mut store, &mut index, "app", v(1, 0, 0), b"app-1.0.0");
        let mut inst = Installer::new();
        inst.install(&index, &store, &pn("app"), v(1, 0, 0))
            .expect("install");
        assert_eq!(
            inst.upgrade(&index, &store, &pn("app"), v(1, 0, 0)),
            Err(UpgradeError::NothingToUpgrade {
                name: pn("app"),
                current: v(1, 0, 0),
            })
        );
    }

    #[test]
    fn upgrade_is_atomic_when_new_content_is_missing() {
        let mut store = ContentStore::new();
        let mut index = PackageIndex::new();
        add_pkg(&mut store, &mut index, "app", v(1, 0, 0), b"app-1.0.0");
        let mut inst = Installer::new();
        inst.install(&index, &store, &pn("app"), v(1, 0, 0))
            .expect("install");
        // A newer version is then indexed but its content is NOT in the store.
        index.add(PackageManifest::new(
            pn("app"),
            v(1, 1, 0),
            [42; crate::manifest::CONTENT_HASH_LEN],
        ));

        assert_eq!(
            inst.upgrade(&index, &store, &pn("app"), v(1, 0, 0)),
            Err(UpgradeError::ContentMissing(pn("app")))
        );
        // State is unchanged: still 1.0.0, and no rollback point was recorded.
        assert_eq!(
            inst.installed(&pn("app")).map(|p| p.version),
            Some(v(1, 0, 0))
        );
        assert!(inst.previous(&pn("app")).is_none());
    }

    #[test]
    fn rollback_without_previous_fails() {
        let mut inst = Installer::new();
        assert_eq!(
            inst.rollback(&pn("app")),
            Err(RollbackError::NoPreviousVersion(pn("app")))
        );
    }

    // --- Tampered-package rejection (WS9-02.8) ------------------------------

    #[test]
    fn tampered_artifact_is_refused_and_never_installs() {
        use crate::store::content_address;

        // The publisher's manifest declares the hash of the genuine artifact.
        let good = b"app-genuine-bytes";
        let declared = content_address(good);
        let manifest = PackageManifest::new(pn("app"), v(1, 0, 0), declared);
        let mut index = PackageIndex::new();
        index.add(manifest.clone());

        // An attacker supplies tampered bytes for that manifest.
        let mut store = ContentStore::new();
        let err = store
            .put_verified(&manifest.content_hash, b"app-EVIL-bytes".to_vec())
            .expect_err("tampered content must be refused");
        assert_eq!(err.declared, declared);

        // The tampered blob never entered the store, so the install cannot find
        // the content and the package is not installed.
        let mut inst = Installer::new();
        assert_eq!(
            inst.install(&index, &store, &pn("app"), v(1, 0, 0)),
            Err(InstallError::ContentMissing(pn("app")))
        );
        assert!(!inst.is_installed(&pn("app")));

        // The genuine artifact, by contrast, is admitted and installs.
        store
            .put_verified(&manifest.content_hash, good.to_vec())
            .expect("genuine content admitted");
        inst.install(&index, &store, &pn("app"), v(1, 0, 0))
            .expect("genuine install succeeds");
        assert!(inst.is_installed(&pn("app")));
    }
}

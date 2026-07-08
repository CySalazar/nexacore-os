//! Federated package repositories (WS9-02.9).
//!
//! Multiple repositories can each publish package manifests. A [`Federation`]
//! merges them into a single [`PackageIndex`] for resolution, resolving
//! same-`(name, version)` collisions by **repository priority**: a
//! higher-priority (more trusted) repository's manifest shadows a lower-priority
//! one, so an untrusted mirror cannot substitute its own artifact for a package
//! a trusted repository already provides. [`Federation::provider`] reports which
//! repository a given package version came from (provenance).

use crate::{
    install::PackageIndex,
    manifest::{PackageManifest, PackageName, Version},
};

/// A repository identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepoId(pub String);

impl RepoId {
    /// A repository id from a string.
    #[must_use]
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }

    /// The id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One federated repository: its id, trust priority, and available manifests.
#[derive(Debug, Clone)]
pub struct Repository {
    /// The repository id.
    pub id: RepoId,
    /// Trust priority — higher wins a `(name, version)` collision.
    pub priority: u32,
    /// The manifests this repository publishes.
    pub manifests: Vec<PackageManifest>,
}

impl Repository {
    /// A repository with `id` and `priority` and no manifests.
    #[must_use]
    pub fn new(id: RepoId, priority: u32) -> Self {
        Self {
            id,
            priority,
            manifests: Vec::new(),
        }
    }

    /// Add a manifest this repository publishes.
    pub fn publish(&mut self, manifest: PackageManifest) {
        self.manifests.push(manifest);
    }

    fn provides(&self, name: &PackageName, version: Version) -> bool {
        self.manifests
            .iter()
            .any(|m| &m.name == name && m.version == version)
    }
}

/// A federation of package repositories (WS9-02.9).
#[derive(Debug, Clone, Default)]
pub struct Federation {
    repos: Vec<Repository>,
}

impl Federation {
    /// An empty federation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a repository.
    pub fn add_repository(&mut self, repo: Repository) {
        self.repos.push(repo);
    }

    /// The number of federated repositories.
    #[must_use]
    pub fn repository_count(&self) -> usize {
        self.repos.len()
    }

    /// Repositories ordered by decreasing priority, ties broken by id for a
    /// deterministic merge.
    fn by_priority(&self) -> Vec<&Repository> {
        let mut order: Vec<&Repository> = self.repos.iter().collect();
        order.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.id.0.cmp(&b.id.0))
        });
        order
    }

    /// Merge every repository into one [`PackageIndex`]. For each
    /// `(name, version)` the manifest from the highest-priority repository wins;
    /// lower-priority duplicates are dropped.
    #[must_use]
    pub fn merged_index(&self) -> PackageIndex {
        let mut index = PackageIndex::new();
        let mut seen: Vec<(PackageName, Version)> = Vec::new();
        for repo in self.by_priority() {
            for manifest in &repo.manifests {
                let key = (manifest.name.clone(), manifest.version);
                if !seen.contains(&key) {
                    seen.push(key);
                    index.add(manifest.clone());
                }
            }
        }
        index
    }

    /// The id of the repository that authoritatively provides `(name, version)`
    /// — the highest-priority repository publishing it.
    #[must_use]
    pub fn provider(&self, name: &PackageName, version: Version) -> Option<&RepoId> {
        self.by_priority()
            .into_iter()
            .find(|r| r.provides(name, version))
            .map(|r| &r.id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::store::content_address;

    fn pn(s: &str) -> PackageName {
        PackageName::new(s).expect("valid name")
    }

    fn v(a: u32, b: u32, c: u32) -> Version {
        Version::new(a, b, c)
    }

    fn manifest(name: &str, ver: Version, content: &[u8]) -> PackageManifest {
        PackageManifest::new(pn(name), ver, content_address(content))
    }

    #[test]
    fn higher_priority_repo_shadows_a_colliding_version() {
        // Two repos both publish app 1.0.0, with different artifacts.
        let mut trusted = Repository::new(RepoId::new("official"), 100);
        trusted.publish(manifest("app", v(1, 0, 0), b"official-app"));
        let mut mirror = Repository::new(RepoId::new("mirror"), 10);
        mirror.publish(manifest("app", v(1, 0, 0), b"MIRROR-app"));

        let mut fed = Federation::new();
        fed.add_repository(mirror);
        fed.add_repository(trusted);
        assert_eq!(fed.repository_count(), 2);

        // The merged index carries the trusted artifact, not the mirror's.
        let index = fed.merged_index();
        let chosen = index.best(&pn("app"), v(1, 0, 0)).expect("present");
        assert_eq!(chosen.content_hash, content_address(b"official-app"));
        // Provenance points at the trusted repo.
        assert_eq!(
            fed.provider(&pn("app"), v(1, 0, 0)),
            Some(&RepoId::new("official"))
        );
    }

    #[test]
    fn distinct_packages_from_all_repos_are_present() {
        let mut a = Repository::new(RepoId::new("a"), 50);
        a.publish(manifest("alpha", v(1, 0, 0), b"alpha"));
        let mut b = Repository::new(RepoId::new("b"), 40);
        b.publish(manifest("beta", v(2, 0, 0), b"beta"));

        let mut fed = Federation::new();
        fed.add_repository(a);
        fed.add_repository(b);

        let index = fed.merged_index();
        assert!(index.best(&pn("alpha"), v(1, 0, 0)).is_some());
        assert!(index.best(&pn("beta"), v(2, 0, 0)).is_some());
        assert_eq!(
            fed.provider(&pn("beta"), v(2, 0, 0)),
            Some(&RepoId::new("b"))
        );
        assert_eq!(fed.provider(&pn("ghost"), v(1, 0, 0)), None);
    }

    #[test]
    fn different_versions_coexist_across_repos() {
        let mut old = Repository::new(RepoId::new("old"), 30);
        old.publish(manifest("lib", v(1, 0, 0), b"lib-1"));
        let mut new = Repository::new(RepoId::new("new"), 20);
        new.publish(manifest("lib", v(2, 0, 0), b"lib-2"));

        let mut fed = Federation::new();
        fed.add_repository(old);
        fed.add_repository(new);

        let index = fed.merged_index();
        // best(>=1.0.0) picks the highest version across the federation.
        assert_eq!(
            index.best(&pn("lib"), v(1, 0, 0)).map(|m| m.version),
            Some(v(2, 0, 0))
        );
    }
}

//! Service dependency graph and topological start order (WS12-01.3 / .4).
//!
//! [`DependencyGraph`] is built from a set of [`ServiceManifest`]s; each
//! `requires` edge means "must be running before me". [`DependencyGraph::topological_order`]
//! returns a deterministic start order via Kahn's algorithm, rejecting cycles
//! and dangling dependencies.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::fmt;

use crate::{ServiceName, manifest::ServiceManifest};

/// A dependency graph over a set of services.
#[derive(Clone, Debug, Default)]
pub struct DependencyGraph {
    /// For each service, the set of services it requires (its prerequisites).
    requires: BTreeMap<ServiceName, BTreeSet<ServiceName>>,
}

impl DependencyGraph {
    /// Builds a graph from the given manifests.
    ///
    /// # Errors
    ///
    /// - [`GraphError::DuplicateService`] if two manifests share a name.
    /// - [`GraphError::UnknownDependency`] if a `requires` entry names a service
    ///   not present in the manifest set.
    pub fn from_manifests<'a, I>(manifests: I) -> Result<Self, GraphError>
    where
        I: IntoIterator<Item = &'a ServiceManifest>,
    {
        let mut requires: BTreeMap<ServiceName, BTreeSet<ServiceName>> = BTreeMap::new();
        for m in manifests {
            if requires.contains_key(&m.name) {
                return Err(GraphError::DuplicateService(m.name.clone()));
            }
            requires.insert(m.name.clone(), m.requires.iter().cloned().collect());
        }
        for (svc, deps) in &requires {
            for dep in deps {
                if !requires.contains_key(dep) {
                    return Err(GraphError::UnknownDependency {
                        service: svc.clone(),
                        dependency: dep.clone(),
                    });
                }
            }
        }
        Ok(Self { requires })
    }

    /// Number of services in the graph.
    #[must_use]
    pub fn len(&self) -> usize {
        self.requires.len()
    }

    /// Returns `true` if the graph has no services.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requires.is_empty()
    }

    /// Returns the direct prerequisites of a service, if it exists.
    #[must_use]
    pub fn prerequisites(&self, service: &ServiceName) -> Option<&BTreeSet<ServiceName>> {
        self.requires.get(service)
    }

    /// Returns a deterministic topological start order: every service appears
    /// after all of its prerequisites.
    ///
    /// Ties are broken by name so the order is stable across runs. The reverse
    /// of this order is the correct *shutdown* order.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::Cycle`] if the dependencies contain a cycle.
    pub fn topological_order(&self) -> Result<Vec<ServiceName>, GraphError> {
        // Kahn's algorithm. in_degree[s] = number of unmet prerequisites of s.
        // in_degree[s] = number of prerequisites of s (incoming edges).
        let mut in_degree: BTreeMap<&ServiceName, usize> = self
            .requires
            .iter()
            .map(|(s, deps)| (s, deps.len()))
            .collect();

        // ready = services with all prerequisites met, kept sorted by name
        // (BTreeSet iteration is ordered) for deterministic output.
        let mut ready: BTreeSet<&ServiceName> = in_degree
            .iter()
            .filter_map(|(s, d)| (*d == 0).then_some(*s))
            .collect();

        let mut order: Vec<ServiceName> = Vec::with_capacity(self.requires.len());
        while let Some(next) = ready.iter().next().copied() {
            ready.remove(next);
            order.push(next.clone());
            // Relax every dependent of `next`: a service depends on `next` if
            // `next` is in its `requires` set.
            for (svc, deps) in &self.requires {
                if deps.contains(next) {
                    if let Some(slot) = in_degree.get_mut(svc) {
                        *slot = slot.saturating_sub(1);
                        if *slot == 0 {
                            ready.insert(svc);
                        }
                    }
                }
            }
        }

        if order.len() == self.requires.len() {
            Ok(order)
        } else {
            // Whatever remains with a non-zero in-degree is part of a cycle.
            let stuck = in_degree
                .iter()
                .filter_map(|(s, d)| (*d > 0).then_some((*s).clone()))
                .collect();
            Err(GraphError::Cycle(stuck))
        }
    }
}

/// Error returned when building or ordering a [`DependencyGraph`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphError {
    /// Two manifests declared the same service name.
    DuplicateService(ServiceName),
    /// A service required a name absent from the manifest set.
    UnknownDependency {
        /// The service that declared the dependency.
        service: ServiceName,
        /// The missing dependency.
        dependency: ServiceName,
    },
    /// The dependency graph contains a cycle (the listed services are involved).
    Cycle(Vec<ServiceName>),
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateService(s) => write!(f, "duplicate service {s}"),
            Self::UnknownDependency {
                service,
                dependency,
            } => {
                write!(f, "service {service} requires unknown service {dependency}")
            }
            Self::Cycle(svcs) => {
                f.write_str("dependency cycle among:")?;
                for s in svcs {
                    write!(f, " {s}")?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::manifest::ServiceManifest;

    fn svc(name: &str, deps: &[&str]) -> ServiceManifest {
        ServiceManifest::new(name, "/bin/x")
            .unwrap()
            .requires(deps.iter().copied())
            .unwrap()
    }

    fn name(s: &str) -> ServiceName {
        ServiceName::new(s).unwrap()
    }

    #[test]
    fn topological_order_respects_dependencies() {
        // net requires log; ui requires net; log requires nothing.
        let manifests = vec![svc("ui", &["net"]), svc("net", &["log"]), svc("log", &[])];
        let g = DependencyGraph::from_manifests(&manifests).unwrap();
        let order = g.topological_order().unwrap();
        let pos = |n: &str| order.iter().position(|s| s.as_str() == n).unwrap();
        assert!(pos("log") < pos("net"));
        assert!(pos("net") < pos("ui"));
        // Deterministic: independent roots come out name-sorted.
        assert_eq!(order, vec![name("log"), name("net"), name("ui")]);
    }

    #[test]
    fn independent_services_are_name_sorted() {
        let manifests = vec![svc("c", &[]), svc("a", &[]), svc("b", &[])];
        let g = DependencyGraph::from_manifests(&manifests).unwrap();
        assert_eq!(
            g.topological_order().unwrap(),
            vec![name("a"), name("b"), name("c")]
        );
    }

    #[test]
    fn cycle_is_detected() {
        let manifests = vec![svc("a", &["b"]), svc("b", &["a"])];
        let g = DependencyGraph::from_manifests(&manifests).unwrap();
        match g.topological_order() {
            Err(GraphError::Cycle(mut stuck)) => {
                stuck.sort();
                assert_eq!(stuck, vec![name("a"), name("b")]);
            }
            other => panic!("expected cycle, got {other:?}"),
        }
    }

    #[test]
    fn unknown_dependency_is_rejected() {
        let manifests = vec![svc("a", &["ghost"])];
        let err = DependencyGraph::from_manifests(&manifests).unwrap_err();
        assert_eq!(
            err,
            GraphError::UnknownDependency {
                service: name("a"),
                dependency: name("ghost")
            }
        );
    }

    #[test]
    fn duplicate_service_is_rejected() {
        let manifests = vec![svc("a", &[]), svc("a", &[])];
        assert_eq!(
            DependencyGraph::from_manifests(&manifests).unwrap_err(),
            GraphError::DuplicateService(name("a"))
        );
    }
}

//! ncScript module system: cross-module import resolution (WS18-06.1/.2).
//!
//! A *module* is a parsed [`Program`] registered under a name. Its **exports**
//! are its top-level named items (functions, structs, enums, constants); its
//! **imports** are its `use` paths (already parsed into [`Item::Use`] by the
//! existing lexer/parser). A `use a::b` reads symbol `b` from module `a`.
//!
//! [`ModuleGraph::resolve`] is the resolver (WS18-06.2): for every import that
//! names a *registered* module it checks the imported symbol is exported, builds
//! the module dependency graph, and returns a topological load order
//! (dependencies first) — or a [`ModuleError`] for a missing export or an import
//! cycle. Imports whose first segment is **not** a registered module (e.g. the
//! built-in `string::`/`math::` stdlib namespaces) are treated as external and
//! left untouched.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};

use crate::ast::{CapDecl, CapScope, Item, Program};

/// An error from [`ModuleGraph::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleError {
    /// `use <module>::<symbol>` named a registered module that has no such
    /// export.
    UnknownExport {
        /// The importing module is irrelevant; this is the *target* module.
        module: String,
        /// The symbol that was not exported.
        symbol: String,
    },
    /// A cycle of module imports. The vector lists the modules on the cycle, in
    /// traversal order, with the repeated module closing the loop (e.g.
    /// `["a", "b", "a"]`).
    ImportCycle(Vec<String>),
}

/// The top-level exported name of an item, if it has one.
fn item_name(item: &Item) -> Option<&str> {
    match item {
        Item::Fn(f) => Some(&f.name),
        Item::Struct(s) => Some(&s.name),
        Item::Enum(e) => Some(&e.name),
        Item::Const(c) => Some(&c.name),
        // `use` and `impl` introduce no exported name.
        Item::Use(_) | Item::Impl(_) => None,
    }
}

/// A named collection of parsed modules with import resolution (WS18-06.1).
#[derive(Debug, Default)]
pub struct ModuleGraph {
    modules: BTreeMap<String, Program>,
}

impl ModuleGraph {
    /// An empty module graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) the module `name` with its parsed program.
    pub fn insert(&mut self, name: impl Into<String>, program: Program) {
        self.modules.insert(name.into(), program);
    }

    /// Whether a module named `name` is registered.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.modules.contains_key(name)
    }

    /// The number of registered modules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Whether the graph has no modules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// The exported top-level item names of module `name`, if registered.
    #[must_use]
    pub fn exports_of(&self, name: &str) -> Option<Vec<&str>> {
        self.modules
            .get(name)
            .map(|prog| prog.items.iter().filter_map(item_name).collect())
    }

    /// Resolve all cross-module imports (WS18-06.2).
    ///
    /// Returns a topological load order (each module after the modules it
    /// imports from).
    ///
    /// # Errors
    ///
    /// [`ModuleError::UnknownExport`] if an import names a registered module
    /// without that export, or [`ModuleError::ImportCycle`] if the import graph
    /// has a cycle.
    pub fn resolve(&self) -> Result<Vec<String>, ModuleError> {
        // Validate exports and build the dependency adjacency (registered
        // modules only; unknown prefixes are external/stdlib and ignored).
        let mut deps: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for name in self.modules.keys() {
            deps.insert(name.as_str(), BTreeSet::new());
        }
        for (name, prog) in &self.modules {
            for item in &prog.items {
                let Item::Use(path) = item else { continue };
                let Some(target) = path.first() else { continue };
                if target == name {
                    continue; // self-import: not a cross-module edge
                }
                let Some(target_prog) = self.modules.get(target) else {
                    continue; // external (e.g. `string::len`) — not a module
                };
                // If a specific symbol is named, it must be exported.
                if let Some(symbol) = path.get(1) {
                    let exported = target_prog
                        .items
                        .iter()
                        .filter_map(item_name)
                        .any(|n| n == symbol);
                    if !exported {
                        return Err(ModuleError::UnknownExport {
                            module: target.clone(),
                            symbol: symbol.clone(),
                        });
                    }
                }
                if let Some(edges) = deps.get_mut(name.as_str()) {
                    edges.insert(target.as_str());
                }
            }
        }

        // Depth-first topological sort with cycle detection.
        let mut color: BTreeMap<&str, Color> = BTreeMap::new();
        let mut order: Vec<&str> = Vec::new();
        let mut path: Vec<&str> = Vec::new();
        for name in self.modules.keys() {
            if color.get(name.as_str()).copied().unwrap_or(Color::White) == Color::White {
                visit(name.as_str(), &deps, &mut color, &mut order, &mut path)?;
            }
        }
        Ok(order.into_iter().map(String::from).collect())
    }

    /// Build the package capability manifest (WS18-06.3): the deduplicated union
    /// of every registered module's declared `#![capabilities(...)]`.
    ///
    /// This is the surface a package runner reviews and gates at first run
    /// (WS18-06.5/.6): it is the complete set of effects the package may request,
    /// independent of which module declares each one.
    #[must_use]
    pub fn package_manifest(
        &self,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> PackageManifest {
        let mut capabilities: Vec<CapDecl> = Vec::new();
        for prog in self.modules.values() {
            for cap in &prog.capabilities {
                if !capabilities.contains(cap) {
                    capabilities.push(cap.clone());
                }
            }
        }
        // Deterministic order: by capability name, then by scope.
        capabilities.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| scope_key(a.scope.as_ref()).cmp(&scope_key(b.scope.as_ref())))
        });
        PackageManifest {
            name: name.into(),
            version: version.into(),
            capabilities,
        }
    }
}

/// A sortable key for an optional capability scope, for deterministic ordering.
fn scope_key(scope: Option<&CapScope>) -> String {
    match scope {
        None => String::new(),
        Some(CapScope::Str(s)) => {
            let mut k = String::from("s:");
            k.push_str(s);
            k
        }
        Some(CapScope::Int(i)) => {
            let mut k = String::from("i:");
            k.push_str(&i.to_string());
            k
        }
    }
}

/// The capability manifest of an ncScript package (WS18-06.3): its identity
/// plus the deduplicated set of capabilities its modules declare.
#[derive(Debug, Clone, PartialEq)]
pub struct PackageManifest {
    /// Package name.
    pub name: String,
    /// Package version (opaque string).
    pub version: String,
    /// The deduplicated, deterministically-ordered capabilities the package may
    /// request across all its modules.
    pub capabilities: Vec<CapDecl>,
}

impl PackageManifest {
    /// Whether the package declares any capability with the dotted `name`
    /// (regardless of scope).
    #[must_use]
    pub fn requires(&self, name: &str) -> bool {
        self.capabilities.iter().any(|c| c.name == name)
    }

    /// Whether the package declares no capabilities at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }
}

/// DFS visit color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Color {
    /// Unvisited.
    White,
    /// On the current DFS stack.
    Gray,
    /// Fully processed.
    Black,
}

/// Post-order DFS, pushing each node after its dependencies (topological order).
fn visit<'a>(
    node: &'a str,
    deps: &BTreeMap<&'a str, BTreeSet<&'a str>>,
    color: &mut BTreeMap<&'a str, Color>,
    order: &mut Vec<&'a str>,
    path: &mut Vec<&'a str>,
) -> Result<(), ModuleError> {
    color.insert(node, Color::Gray);
    path.push(node);
    if let Some(neighbors) = deps.get(node) {
        for &dep in neighbors {
            match color.get(dep).copied().unwrap_or(Color::White) {
                Color::White => visit(dep, deps, color, order, path)?,
                Color::Gray => {
                    // Back-edge: report the cycle from `dep` to the stack top.
                    let start = path.iter().position(|n| *n == dep).unwrap_or(0);
                    let mut cycle: Vec<String> = path
                        .get(start..)
                        .unwrap_or(&[])
                        .iter()
                        .map(|s| String::from(*s))
                        .collect();
                    cycle.push(String::from(dep));
                    return Err(ModuleError::ImportCycle(cycle));
                }
                Color::Black => {}
            }
        }
    }
    path.pop();
    color.insert(node, Color::Black);
    order.push(node);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::parser::parse;

    fn graph(modules: &[(&str, &str)]) -> ModuleGraph {
        let mut g = ModuleGraph::new();
        for (name, src) in modules {
            g.insert(*name, parse(src).unwrap());
        }
        g
    }

    #[test]
    fn exports_are_top_level_named_items() {
        let g = graph(&[("m", "fn f() {}\nstruct S;\nenum E { A }\nconst C: int = 1;")]);
        let mut exports = g.exports_of("m").unwrap();
        exports.sort_unstable();
        assert_eq!(exports, alloc::vec!["C", "E", "S", "f"]);
        assert!(g.exports_of("absent").is_none());
    }

    #[test]
    fn linear_imports_resolve_in_dependency_order() {
        // a uses b::y; b uses c::z; c is a leaf.
        let g = graph(&[
            ("a", "use b::y;\nfn main() {}"),
            ("b", "use c::z;\nfn y() {}"),
            ("c", "fn z() {}"),
        ]);
        let order = g.resolve().unwrap();
        let pos = |name: &str| order.iter().position(|m| m == name).unwrap();
        // Dependencies come before dependents.
        assert!(pos("c") < pos("b"));
        assert!(pos("b") < pos("a"));
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn external_namespaces_are_ignored() {
        // `string` / `math` are not registered modules → treated as external.
        let g = graph(&[("a", "use string::len;\nuse math::abs;\nfn main() {}")]);
        assert_eq!(g.resolve().unwrap(), alloc::vec![String::from("a")]);
    }

    #[test]
    fn missing_export_is_reported() {
        let g = graph(&[("a", "use b::nope;\nfn main() {}"), ("b", "fn other() {}")]);
        assert_eq!(
            g.resolve(),
            Err(ModuleError::UnknownExport {
                module: String::from("b"),
                symbol: String::from("nope"),
            })
        );
    }

    #[test]
    fn import_cycle_is_detected() {
        // a -> b -> a (both exports exist).
        let g = graph(&[("a", "use b::y;\nfn x() {}"), ("b", "use a::x;\nfn y() {}")]);
        match g.resolve() {
            Err(ModuleError::ImportCycle(cycle)) => {
                assert!(cycle.contains(&String::from("a")));
                assert!(cycle.contains(&String::from("b")));
                // The cycle closes on itself.
                assert_eq!(cycle.first(), cycle.last());
            }
            other => panic!("expected ImportCycle, got {other:?}"),
        }
    }

    #[test]
    fn whole_module_import_needs_no_symbol_check() {
        // `use b;` imports the module without naming a symbol.
        let g = graph(&[("a", "use b;\nfn main() {}"), ("b", "fn y() {}")]);
        let order = g.resolve().unwrap();
        assert!(
            order.iter().position(|m| m == "b").unwrap()
                < order.iter().position(|m| m == "a").unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Package capability manifest (WS18-06.3)
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_unions_and_dedups_module_capabilities() {
        let g = graph(&[
            (
                "a",
                "#![capabilities(fs.read(\"/etc\"), ai.invoke)]\nfn main() {}",
            ),
            // `ai.invoke` is declared again (must dedup); `net.connect` is new.
            ("b", "#![capabilities(ai.invoke, net.connect)]\nfn y() {}"),
        ]);
        let manifest = g.package_manifest("demo", "1.0.0");
        assert_eq!(manifest.name, "demo");
        assert_eq!(manifest.version, "1.0.0");
        // Union with dedup: ai.invoke, fs.read, net.connect → 3 distinct.
        assert_eq!(manifest.capabilities.len(), 3);
        assert!(manifest.requires("fs.read"));
        assert!(manifest.requires("ai.invoke"));
        assert!(manifest.requires("net.connect"));
        assert!(!manifest.requires("proc.spawn"));
        // Deterministic order: sorted by capability name.
        let names: Vec<&str> = manifest
            .capabilities
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, alloc::vec!["ai.invoke", "fs.read", "net.connect"]);
    }

    #[test]
    fn manifest_keeps_same_name_distinct_scopes() {
        let g = graph(&[(
            "a",
            "#![capabilities(fs.read(\"/etc\"), fs.read(\"/var\"))]\nfn main() {}",
        )]);
        let manifest = g.package_manifest("pkg", "0.1");
        // Same name, different scope → two distinct capabilities.
        assert_eq!(manifest.capabilities.len(), 2);
        assert!(manifest.requires("fs.read"));
    }

    #[test]
    fn manifest_is_empty_without_declarations() {
        let g = graph(&[("a", "fn main() {}")]);
        let manifest = g.package_manifest("pkg", "0.1");
        assert!(manifest.is_empty());
        assert!(!manifest.requires("fs.read"));
    }
}

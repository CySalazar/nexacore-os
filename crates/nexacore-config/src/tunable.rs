//! Safe, capability-bound system tunables (WS17-06.1/.2).
//!
//! "Extreme configurability" must reach kernel and service knobs, but without
//! foot-guns. This module catalogs the tunables NexaCore exposes — scheduler
//! policy, network parameters, FS cache, power policy, privacy-budget
//! thresholds — and classifies each as [`RiskLevel::Safe`] or
//! [`RiskLevel::Risky`].
//!
//! [`register_safe_tunables`] installs the **safe** subset into a
//! [`SchemaRegistry`] (WS17-01), so a [`ConfigStore`](crate::ConfigStore)
//! validates writes to them against type + range exactly like any other key.
//! The risky subset is deliberately *not* registered here: those stay behind
//! the NexaCore Helper escalation gate (WS17-06.7) and the actual kernel/service
//! bindings (WS17-06.3/.4/.5) wire them once those subsystems exist.

use alloc::{string::String, vec, vec::Vec};

use crate::{
    ConfigError, Key,
    schema::{KeySchema, SchemaRegistry},
    value::{ConfigValue, ValueType},
};

/// How dangerous it is to change a tunable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    /// Bounded, reversible, and free of system-integrity foot-guns; exposed
    /// directly in the config store.
    Safe,
    /// Can degrade stability, security, or data integrity; gated behind Helper
    /// escalation (WS17-06.7) rather than exposed directly.
    Risky,
}

/// The specification of one system tunable.
#[derive(Debug, Clone)]
pub struct TunableSpec {
    /// The config-store key (a dotted, lowercase [`Key`] string).
    pub key: &'static str,
    /// The value type and its range/constraints.
    pub ty: ValueType,
    /// The default value (must satisfy `ty`).
    pub default: ConfigValue,
    /// Human-readable description.
    pub description: &'static str,
    /// Whether the tunable is safe to expose directly.
    pub risk: RiskLevel,
}

impl TunableSpec {
    /// Whether this tunable is [`RiskLevel::Safe`].
    #[must_use]
    pub fn is_safe(&self) -> bool {
        self.risk == RiskLevel::Safe
    }
}

/// The full catalog of kernel/service tunables (WS17-06.1), safe and risky.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "a flat declarative data table; one block per tunable is clearest"
)]
pub fn catalog() -> Vec<TunableSpec> {
    vec![
        // -- Scheduler -------------------------------------------------------
        TunableSpec {
            key: "kernel.sched.policy",
            ty: ValueType::Enum(&["fair", "batch", "idle"]),
            default: ConfigValue::Str(String::from("fair")),
            description: "default process scheduling class",
            risk: RiskLevel::Safe,
        },
        TunableSpec {
            key: "kernel.sched.preempt",
            ty: ValueType::Bool,
            default: ConfigValue::Bool(true),
            description: "allow kernel preemption of running tasks",
            risk: RiskLevel::Safe,
        },
        TunableSpec {
            // Foot-gun: starving the RT runtime can lock up the system.
            key: "kernel.sched.rt_runtime_us",
            ty: ValueType::Int {
                min: 0,
                max: 1_000_000,
            },
            default: ConfigValue::Int(950_000),
            description: "microseconds per period reserved for real-time tasks",
            risk: RiskLevel::Risky,
        },
        // -- Memory ----------------------------------------------------------
        TunableSpec {
            // Foot-gun: `always` overcommit invites the OOM killer.
            key: "kernel.mm.overcommit",
            ty: ValueType::Enum(&["heuristic", "always", "never"]),
            default: ConfigValue::Str(String::from("heuristic")),
            description: "memory overcommit policy",
            risk: RiskLevel::Risky,
        },
        // -- Network ---------------------------------------------------------
        TunableSpec {
            key: "net.tcp.congestion",
            ty: ValueType::Enum(&["reno", "cubic", "bbr"]),
            default: ConfigValue::Str(String::from("cubic")),
            description: "TCP congestion control algorithm",
            risk: RiskLevel::Safe,
        },
        TunableSpec {
            key: "net.tcp.rto_min_ms",
            ty: ValueType::Int {
                min: 10,
                max: 60_000,
            },
            default: ConfigValue::Int(200),
            description: "minimum TCP retransmission timeout in milliseconds",
            risk: RiskLevel::Safe,
        },
        TunableSpec {
            // Foot-gun: turns the host into a router, changing its trust model.
            key: "net.ip.forward",
            ty: ValueType::Bool,
            default: ConfigValue::Bool(false),
            description: "forward IP packets between interfaces (act as a router)",
            risk: RiskLevel::Risky,
        },
        // -- Filesystem cache ------------------------------------------------
        TunableSpec {
            key: "fs.cache.writeback_ms",
            ty: ValueType::Int {
                min: 0,
                max: 600_000,
            },
            default: ConfigValue::Int(5_000),
            description: "dirty-page writeback interval in milliseconds",
            risk: RiskLevel::Safe,
        },
        TunableSpec {
            key: "fs.cache.max_dirty_mb",
            ty: ValueType::Int {
                min: 0,
                max: 65_536,
            },
            default: ConfigValue::Int(256),
            description: "maximum dirty page cache before forced writeback (MiB)",
            risk: RiskLevel::Safe,
        },
        TunableSpec {
            // Foot-gun: disabling write barriers risks data loss on power cut.
            key: "fs.cache.write_barriers",
            ty: ValueType::Bool,
            default: ConfigValue::Bool(true),
            description: "enforce write barriers for crash consistency",
            risk: RiskLevel::Risky,
        },
        // -- Power -----------------------------------------------------------
        TunableSpec {
            key: "power.policy",
            ty: ValueType::Enum(&["performance", "balanced", "powersave"]),
            default: ConfigValue::Str(String::from("balanced")),
            description: "system power/performance profile",
            risk: RiskLevel::Safe,
        },
        // -- Privacy budget --------------------------------------------------
        TunableSpec {
            key: "privacy.budget.daily_limit",
            ty: ValueType::Int {
                min: 0,
                max: 1_000_000,
            },
            default: ConfigValue::Int(100),
            description: "daily privacy-egress budget (units, 0 = local-only)",
            risk: RiskLevel::Safe,
        },
    ]
}

/// Register every [`RiskLevel::Safe`] tunable from the [`catalog`] into `reg`
/// (WS17-06.2), returning how many were registered.
///
/// # Errors
///
/// [`ConfigError`] if a catalog entry has an invalid key or a default that does
/// not satisfy its type — both of which indicate a catalog bug, surfaced by the
/// `every_catalog_default_is_valid` test before it ever ships.
pub fn register_safe_tunables(reg: &mut SchemaRegistry) -> Result<usize, ConfigError> {
    let mut count = 0;
    for spec in catalog().into_iter().filter(TunableSpec::is_safe) {
        let key = Key::new(spec.key)?;
        let schema = KeySchema::new(spec.ty, spec.default, spec.description)?;
        reg.register(key, schema);
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{
        ConfigStore,
        declarative::import_profile,
        store::{AllowAll, MemoryBackend},
    };

    #[test]
    fn every_catalog_default_is_valid() {
        // A catalog entry whose default violates its own type/range would be a
        // latent bug; KeySchema::new validates the default.
        for spec in catalog() {
            assert!(
                KeySchema::new(spec.ty, spec.default, spec.description).is_ok(),
                "invalid default for tunable {}",
                spec.key
            );
        }
    }

    #[test]
    fn catalog_has_both_safe_and_risky_entries() {
        let cat = catalog();
        assert!(cat.iter().any(TunableSpec::is_safe));
        assert!(cat.iter().any(|s| s.risk == RiskLevel::Risky));
    }

    #[test]
    fn register_installs_only_safe_tunables() {
        let mut reg = SchemaRegistry::new();
        let n = register_safe_tunables(&mut reg).unwrap();
        let expected_safe = catalog().iter().filter(|s| s.is_safe()).count();
        assert_eq!(n, expected_safe);
        assert_eq!(reg.len(), expected_safe);
        // A known safe tunable is present; a known risky one is absent.
        assert!(reg.contains(&Key::new("kernel.sched.policy").unwrap()));
        assert!(reg.contains(&Key::new("net.tcp.rto_min_ms").unwrap()));
        assert!(!reg.contains(&Key::new("net.ip.forward").unwrap()));
        assert!(!reg.contains(&Key::new("fs.cache.write_barriers").unwrap()));
    }

    #[test]
    fn safe_tunables_are_range_validated_in_the_store() {
        let mut reg = SchemaRegistry::new();
        register_safe_tunables(&mut reg).unwrap();
        let mut store = ConfigStore::new(reg, MemoryBackend::new());

        // A valid enum value applies.
        import_profile("kernel.sched.policy = batch", &mut store, &AllowAll).unwrap();
        assert_eq!(
            store
                .get(&Key::new("kernel.sched.policy").unwrap(), None)
                .unwrap(),
            ConfigValue::Str("batch".into())
        );
        // An out-of-enum value is rejected by the schema.
        assert!(import_profile("kernel.sched.policy = bogus", &mut store, &AllowAll).is_err());
        // An out-of-range integer is rejected.
        assert!(import_profile("net.tcp.rto_min_ms = 5", &mut store, &AllowAll).is_err());
        assert!(import_profile("net.tcp.rto_min_ms = 999999", &mut store, &AllowAll).is_err());
        // A value within range applies.
        import_profile("net.tcp.rto_min_ms = 300", &mut store, &AllowAll).unwrap();
        assert_eq!(
            store
                .get(&Key::new("net.tcp.rto_min_ms").unwrap(), None)
                .unwrap(),
            ConfigValue::Int(300)
        );
    }
}

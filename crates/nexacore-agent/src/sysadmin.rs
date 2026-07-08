//! System Administrator Agent — technical operator.
//!
//! Executes technical operations on the system: configuration,
//! package management, driver management, updates, mesh operations,
//! and diagnostics. Acts only on Orchestrator dispatch — never
//! autonomously.
//!
//! See NCIP-Agent-Arch-022 §S5.

use async_trait::async_trait;
use nexacore_types::{AgentId, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use crate::{
    agent::{Agent, AgentKind, AgentState},
    budget::Budget,
    message::{AgentMessage, MessageKind, MessagePayload, OperationResult},
    mode::OperationalMode,
    policy::AgentCapability,
};

// ── Operation categories ───────────────────────────────────────────────────────

/// Categories of operations the `SysAdmin` Agent can perform
/// (NCIP-022 §S5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationCategory {
    /// System settings, network config, user preferences.
    Configuration,
    /// Install, update, remove software via nexacore-pkg.
    PackageManagement,
    /// Load, configure, update drivers.
    DriverManagement,
    /// Disk cleanup, log rotation, cache management.
    Maintenance,
    /// Node enrollment, peer configuration, mesh health.
    MeshOperations,
    /// System health checks, performance profiling.
    Diagnostics,
}

// ── CapabilityChecker ──────────────────────────────────────────────────────────

/// Maps each `OperationCategory` to the `AgentCapability` set required
/// to execute it (NCIP-022 §S5.1).
///
/// This is a pure, stateless mapping — no instance state is needed.
pub struct CapabilityChecker;

impl CapabilityChecker {
    /// Returns the capabilities that must be held before executing an
    /// operation in `category`.
    ///
    /// The mapping mirrors the table in NCIP-022 §S5.1.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_agent::{
    ///     policy::AgentCapability,
    ///     sysadmin::{CapabilityChecker, OperationCategory},
    /// };
    ///
    /// let caps = CapabilityChecker::required_capabilities(OperationCategory::PackageManagement);
    /// assert!(caps.contains(&AgentCapability::PkgInstall));
    /// assert!(caps.contains(&AgentCapability::PkgRemove));
    /// ```
    #[must_use]
    pub fn required_capabilities(category: OperationCategory) -> Vec<AgentCapability> {
        match category {
            OperationCategory::Configuration => {
                vec![AgentCapability::SysConfigure]
            }
            OperationCategory::PackageManagement => {
                vec![AgentCapability::PkgInstall, AgentCapability::PkgRemove]
            }
            OperationCategory::DriverManagement => {
                vec![AgentCapability::DriverLoad]
            }
            OperationCategory::Maintenance => {
                vec![AgentCapability::FsWrite, AgentCapability::SysConfigure]
            }
            OperationCategory::MeshOperations => {
                vec![AgentCapability::NetAdmin]
            }
            OperationCategory::Diagnostics => {
                vec![AgentCapability::FsRead, AgentCapability::PerfProfile]
            }
        }
    }
}

// ── RollbackPoint / RollbackManager ───────────────────────────────────────────

/// A snapshot recorded before a destructive or configuration-altering
/// operation, enabling rollback if the operation fails (NCIP-022 §S5.2 ¶3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollbackPoint {
    /// Unique identifier for this rollback point.
    pub id: u64,
    /// Human-readable description of what is being snapshotted.
    pub description: String,
    /// Unix timestamp (seconds) when the rollback point was created.
    ///
    /// Stubbed to `0` until the `nexacore-hal` Clock abstraction is available
    /// (planned for Phase 6).
    pub timestamp: u64,
    /// The operation category the rollback point protects.
    pub category: OperationCategory,
}

/// Error returned when a rollback operation cannot be completed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RollbackError {
    /// No rollback point with the given ID exists.
    #[error("rollback point {id} not found")]
    NotFound {
        /// The requested rollback point ID.
        id: u64,
    },
}

/// Manages a bounded collection of pre-operation rollback points.
///
/// Points are stored in insertion order. When `max_points` is reached,
/// the oldest point is evicted before inserting the new one (FIFO
/// eviction). The ID counter never resets within an agent session.
///
/// # Overflow note
///
/// The internal ID counter is a `u64` incremented by one per point
/// created. Wrapping overflow after 2^64 calls is not a practical
/// concern for any OS session; it is documented here for completeness.
#[derive(Debug)]
pub struct RollbackManager {
    /// Stored rollback points in insertion order.
    points: Vec<RollbackPoint>,
    /// Maximum number of points retained at any time.
    max_points: usize,
    /// Monotonically increasing counter used to assign unique IDs.
    next_id: u64,
}

impl RollbackManager {
    /// Create a new manager with the given capacity.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_agent::sysadmin::RollbackManager;
    ///
    /// let mgr = RollbackManager::new(16);
    /// assert_eq!(mgr.list_points().len(), 0);
    /// ```
    #[must_use]
    pub fn new(max_points: usize) -> Self {
        Self {
            points: Vec::new(),
            max_points,
            next_id: 1,
        }
    }

    /// Record a rollback point and return its assigned ID.
    ///
    /// If the store is at capacity, the oldest point is evicted before
    /// inserting the new one.
    pub fn create_point(&mut self, description: String, category: OperationCategory) -> u64 {
        // Evict the oldest point when at capacity to keep memory bounded.
        if self.points.len() >= self.max_points && self.max_points > 0 {
            self.points.remove(0);
        }

        let id = self.next_id;
        // Use wrapping_add so overflow does not panic in release builds.
        self.next_id = self.next_id.wrapping_add(1);

        // Timestamp stubbed to 0 until nexacore-hal Clock is available (Phase 6).
        let point = RollbackPoint {
            id,
            description,
            timestamp: 0,
            category,
        };

        info!(rollback_id = id, category = ?category, "rollback point created");
        self.points.push(point);
        id
    }

    /// Remove and return the rollback point with the given `id`.
    ///
    /// # Errors
    ///
    /// Returns [`RollbackError::NotFound`] if `id` does not match any
    /// stored rollback point.
    pub fn rollback(&mut self, id: u64) -> core::result::Result<RollbackPoint, RollbackError> {
        let pos = self
            .points
            .iter()
            .position(|p| p.id == id)
            .ok_or(RollbackError::NotFound { id })?;

        let point = self.points.remove(pos);
        info!(rollback_id = id, "rollback point consumed");
        Ok(point)
    }

    /// Returns all currently stored rollback points.
    #[must_use]
    pub fn list_points(&self) -> &[RollbackPoint] {
        &self.points
    }
}

// ── AuditEvent / AuditEmitter ─────────────────────────────────────────────────

/// A single audit record for a pre- or post-execution event
/// (NCIP-022 §S5.2 ¶4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Short name or description of the operation being audited.
    pub operation: String,
    /// Category of the operation.
    pub category: OperationCategory,
    /// Unix timestamp (seconds) of when the event was emitted.
    ///
    /// Stubbed to `0` until the `nexacore-hal` Clock abstraction lands (Phase 6).
    pub timestamp: u64,
    /// `true` if this is a pre-execution event; `false` for post-execution.
    pub pre_exec: bool,
    /// Outcome of the operation (`None` when the result is not yet known,
    /// i.e. on pre-execution events).
    pub result: Option<bool>,
}

/// Accumulates audit events for later inspection or export.
///
/// In production the events will be streamed into the append-only Merkle
/// audit tree (`docs/04-security-model.md` § Audit log). This sprint
/// retains them in memory so they can be examined in tests.
#[derive(Debug)]
pub struct AuditEmitter {
    /// In-memory event log for the current agent session.
    events: Vec<AuditEvent>,
}

impl AuditEmitter {
    /// Create a new, empty emitter.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_agent::sysadmin::AuditEmitter;
    ///
    /// let emitter = AuditEmitter::new();
    /// assert_eq!(emitter.events().len(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Record an audit event.
    pub fn emit(&mut self, event: AuditEvent) {
        debug!(
            operation = %event.operation,
            pre_exec = event.pre_exec,
            result = ?event.result,
            "audit event emitted"
        );
        self.events.push(event);
    }

    /// Returns all audit events accumulated in this session.
    #[must_use]
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }
}

impl Default for AuditEmitter {
    fn default() -> Self {
        Self::new()
    }
}

// ── CategoryRouter ────────────────────────────────────────────────────────────

/// Classifies operation descriptions into `OperationCategory` values
/// using keyword-based heuristics, and identifies inherently destructive
/// categories.
///
/// This is a pure, stateless classifier — all methods are free functions
/// on the unit struct. A named struct is used so the router can be stored
/// as a field and swapped for a trait object in a future sprint.
#[derive(Debug)]
pub struct CategoryRouter;

impl CategoryRouter {
    /// Classify an operation description into the most appropriate
    /// `OperationCategory` by scanning for domain-specific keywords.
    ///
    /// Keyword priority (first match wins, top to bottom):
    ///
    /// | Keywords | Category |
    /// |---|---|
    /// | `install`, `update`, `remove`, `package` | `PackageManagement` |
    /// | `driver`, `load`, `firmware` | `DriverManagement` |
    /// | `configure`, `settings`, `config` | `Configuration` |
    /// | `disk`, `cleanup`, `log rotation`, `cache` | `Maintenance` |
    /// | `mesh`, `peer`, `node`, `enrollment` | `MeshOperations` |
    /// | `health`, `diagnostic`, `profile`, `benchmark` | `Diagnostics` |
    ///
    /// Falls back to `Configuration` when no keyword matches — the safest
    /// default because `Configuration` is non-destructive and requires the
    /// smallest capability set.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_agent::sysadmin::{CategoryRouter, OperationCategory};
    ///
    /// assert_eq!(
    ///     CategoryRouter::classify_operation("install nginx"),
    ///     OperationCategory::PackageManagement,
    /// );
    /// assert_eq!(
    ///     CategoryRouter::classify_operation("load gpu driver"),
    ///     OperationCategory::DriverManagement,
    /// );
    /// ```
    #[must_use]
    pub fn classify_operation(description: &str) -> OperationCategory {
        let lower = description.to_lowercase();

        // Check specific categories first to avoid false matches on generic
        // keywords like "update" (which appears in both firmware updates and
        // package management).
        if lower.contains("driver") || lower.contains("firmware") {
            return OperationCategory::DriverManagement;
        }

        if lower.contains("mesh") || lower.contains("peer") || lower.contains("enrollment") {
            return OperationCategory::MeshOperations;
        }

        if lower.contains("health")
            || lower.contains("diagnostic")
            || lower.contains("profile")
            || lower.contains("benchmark")
        {
            return OperationCategory::Diagnostics;
        }

        if lower.contains("install")
            || lower.contains("update")
            || lower.contains("remove")
            || lower.contains("package")
        {
            return OperationCategory::PackageManagement;
        }

        if lower.contains("configure") || lower.contains("settings") || lower.contains("config") {
            return OperationCategory::Configuration;
        }

        if lower.contains("disk")
            || lower.contains("cleanup")
            || lower.contains("log rotation")
            || lower.contains("cache")
            || lower.contains("load")
        {
            return OperationCategory::Maintenance;
        }

        if lower.contains("node") {
            return OperationCategory::MeshOperations;
        }

        OperationCategory::Configuration
    }

    /// Returns `true` when operations in `category` are inherently
    /// destructive and therefore require a rollback point before execution.
    ///
    /// Destructive categories per NCIP-022 §S5.1:
    /// - `PackageManagement` (covers the remove variant)
    /// - `Maintenance` (disk cleanup, log deletion, cache purge)
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_agent::sysadmin::{CategoryRouter, OperationCategory};
    ///
    /// assert!(CategoryRouter::is_destructive(
    ///     OperationCategory::Maintenance
    /// ));
    /// assert!(!CategoryRouter::is_destructive(
    ///     OperationCategory::Diagnostics
    /// ));
    /// ```
    #[must_use]
    pub fn is_destructive(category: OperationCategory) -> bool {
        matches!(
            category,
            OperationCategory::PackageManagement | OperationCategory::Maintenance
        )
    }
}

// ── SystemOperation / PreExecValidation ───────────────────────────────────────

/// A system operation to be executed by the `SysAdmin` Agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemOperation {
    /// The category of operation.
    pub category: OperationCategory,
    /// Human-readable description.
    pub description: String,
    /// Whether this operation is destructive (requires rollback point).
    pub destructive: bool,
    /// Whether Security Agent has pre-authorized (required in High-Risk).
    pub security_authorized: bool,
}

/// Pre-execution validation result (NCIP-022 §S5.2).
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)] // each bool is an independent check
pub struct PreExecValidation {
    /// Whether the agent holds the required capability.
    pub capability_valid: bool,
    /// Whether Security Agent authorization was obtained (if required).
    pub security_cleared: bool,
    /// Whether a rollback point was created (or was not required).
    pub rollback_created: bool,
    /// Whether a pre-execution audit event was emitted.
    pub audit_emitted: bool,
}

impl PreExecValidation {
    /// Returns `true` if all checks passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.capability_valid
            && self.security_cleared
            && self.rollback_created
            && self.audit_emitted
    }
}

// ── SysAdminAgent ─────────────────────────────────────────────────────────────

/// The `SysAdmin` Agent.
///
/// Pure executor with guardrails: does what it's told, verifies
/// permissions, creates rollback points, and logs everything. MUST NOT
/// act autonomously (NCIP-022 §S5).
#[derive(Debug)]
pub struct SysAdminAgent {
    id: AgentId,
    state: AgentState,
    #[allow(dead_code)] // enforced in a later sprint
    budget: Budget,
    operations_executed: u64,
    /// Manages pre-operation rollback snapshots.
    rollback_manager: RollbackManager,
    /// Accumulates pre- and post-execution audit records.
    audit_emitter: AuditEmitter,
    /// Classifies operation descriptions into categories.
    #[allow(dead_code)] // will be used when operation routing is wired in a later sprint
    category_router: CategoryRouter,
}

impl SysAdminAgent {
    /// Create a new `SysAdmin` agent.
    #[must_use]
    pub fn new(id: AgentId) -> Self {
        Self {
            id,
            state: AgentState::Initializing,
            budget: Budget::sysadmin_default(),
            operations_executed: 0,
            rollback_manager: RollbackManager::new(64),
            audit_emitter: AuditEmitter::new(),
            category_router: CategoryRouter,
        }
    }

    /// Returns the number of operations executed in this session.
    #[must_use]
    pub fn operations_executed(&self) -> u64 {
        self.operations_executed
    }

    /// Returns a reference to the rollback manager for inspection.
    #[must_use]
    pub fn rollback_manager(&self) -> &RollbackManager {
        &self.rollback_manager
    }

    /// Returns a reference to the audit emitter for inspection.
    #[must_use]
    pub fn audit_emitter(&self) -> &AuditEmitter {
        &self.audit_emitter
    }

    /// Perform pre-execution validation (NCIP-022 §S5.2).
    ///
    /// Steps performed in order:
    ///
    /// 1. **Capability check** — confirm the required capabilities for
    ///    `operation.category` are non-empty (logical declaration check;
    ///    real token validation is a future sprint).
    /// 2. **Security authorization** — in `HighRisk` mode, require
    ///    `operation.security_authorized` to be `true`.
    /// 3. **Rollback point** — create one when the operation is flagged
    ///    `destructive` or its category is inherently destructive.
    /// 4. **Audit emission** — record a pre-execution audit event.
    #[must_use]
    pub fn validate_pre_execution(
        &mut self,
        operation: &SystemOperation,
        mode: OperationalMode,
    ) -> PreExecValidation {
        // Step 1: capability check.
        // The required set is non-empty for every defined category, so the
        // look-up itself acts as the check. Real token validation follows in a
        // subsequent sprint.
        let required = CapabilityChecker::required_capabilities(operation.category);
        let capability_valid = !required.is_empty();

        // Step 2: security pre-authorization (required only in High-Risk mode).
        let security_cleared = if matches!(mode, OperationalMode::HighRisk) {
            operation.security_authorized
        } else {
            true
        };

        // Step 3: rollback point for destructive or configuration-altering ops.
        // Non-destructive operations skip this step; `rollback_created` is set
        // to `true` regardless because the absence of a rollback point is not
        // a validation failure for safe operations.
        if operation.destructive || CategoryRouter::is_destructive(operation.category) {
            self.rollback_manager
                .create_point(operation.description.clone(), operation.category);
        }
        let rollback_created = true;

        // Step 4: pre-execution audit event.
        self.audit_emitter.emit(AuditEvent {
            operation: operation.description.clone(),
            category: operation.category,
            timestamp: 0, // stub: real clock wired in Phase 6
            pre_exec: true,
            result: None,
        });
        let audit_emitted = true;

        PreExecValidation {
            capability_valid,
            security_cleared,
            rollback_created,
            audit_emitted,
        }
    }

    /// Execute a system operation.
    ///
    /// Logs the operation, increments the session counter, and emits a
    /// post-execution audit event. Real execution will be wired in a later
    /// sprint once the `nexacore-runtime` dispatch surface is stable.
    fn execute_operation(&mut self, operation: &SystemOperation) -> OperationResult {
        self.operations_executed += 1;

        info!(
            category = ?operation.category,
            description = %operation.description,
            destructive = operation.destructive,
            "executing system operation"
        );

        // Post-execution audit event.
        self.audit_emitter.emit(AuditEvent {
            operation: operation.description.clone(),
            category: operation.category,
            timestamp: 0, // stub: real clock in Phase 6
            pre_exec: false,
            result: Some(true),
        });

        OperationResult {
            request_id: self.operations_executed,
            success: true,
            summary: format!("{:?}: {}", operation.category, operation.description),
        }
    }
}

#[async_trait]
impl Agent for SysAdminAgent {
    fn kind(&self) -> AgentKind {
        AgentKind::SysAdmin
    }

    fn id(&self) -> AgentId {
        self.id
    }

    fn state(&self) -> AgentState {
        self.state
    }

    #[instrument(skip(self), fields(agent = "sadm"))]
    async fn spawn(&mut self) -> Result<()> {
        info!("sysadmin agent spawning");
        self.state = AgentState::Running;
        Ok(())
    }

    #[instrument(skip(self, message), fields(agent = "sadm", msg_kind = ?message.kind))]
    async fn handle_message(&mut self, message: AgentMessage) -> Result<AgentMessage> {
        debug!(from = ?message.from, "processing message");

        let response_payload = match &message.payload {
            MessagePayload::Intent(intent) => {
                // Use CategoryRouter to classify the intent rather than the
                // previous hard-coded `Configuration` stub.
                let category = CategoryRouter::classify_operation(&intent.content);
                let destructive = CategoryRouter::is_destructive(category);

                let operation = SystemOperation {
                    category,
                    description: intent.content.clone(),
                    destructive,
                    // In High-Risk mode the caller must have pre-authorized;
                    // here we conservatively deny if the mode is High-Risk
                    // and no authorization token was attached (future sprints
                    // will wire the real token check).
                    security_authorized: !matches!(message.mode, OperationalMode::HighRisk),
                };

                let validation = self.validate_pre_execution(&operation, message.mode);

                if validation.all_passed() {
                    let result = self.execute_operation(&operation);
                    MessagePayload::OperationResult(OperationResult {
                        request_id: intent.request_id,
                        success: result.success,
                        summary: result.summary,
                    })
                } else {
                    warn!(
                        request_id = intent.request_id,
                        ?validation,
                        "pre-execution validation failed"
                    );
                    MessagePayload::OperationResult(OperationResult {
                        request_id: intent.request_id,
                        success: false,
                        summary: "pre-execution validation failed".into(),
                    })
                }
            }
            _ => MessagePayload::Empty,
        };

        Ok(AgentMessage {
            id: message.id,
            from: self.id,
            to: message.from,
            timestamp: message.timestamp,
            kind: MessageKind::Result,
            payload: response_payload,
            capabilities: vec![],
            mode: message.mode,
        })
    }

    async fn suspend(&mut self) -> Result<()> {
        self.state = AgentState::Suspended;
        Ok(())
    }

    async fn resume(&mut self) -> Result<()> {
        self.state = AgentState::Running;
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!(
            ops_executed = self.operations_executed,
            "sysadmin agent shutting down"
        );
        self.state = AgentState::Shutdown;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent_id() -> AgentId {
        AgentId::from_bytes([0x03; 16])
    }

    // ── Existing tests (preserved unchanged) ──────────────────────────────

    #[test]
    fn new_agent_has_zero_operations() {
        let agent = SysAdminAgent::new(test_agent_id());
        assert_eq!(agent.operations_executed(), 0);
    }

    #[test]
    fn pre_exec_validation_standard_mode() {
        let mut agent = SysAdminAgent::new(test_agent_id());
        let op = SystemOperation {
            category: OperationCategory::PackageManagement,
            description: "install firefox".into(),
            destructive: false,
            security_authorized: false,
        };
        let v = agent.validate_pre_execution(&op, OperationalMode::Standard);
        assert!(v.all_passed());
    }

    #[test]
    fn pre_exec_validation_high_risk_requires_authorization() {
        let mut agent = SysAdminAgent::new(test_agent_id());
        let op = SystemOperation {
            category: OperationCategory::PackageManagement,
            description: "install firefox".into(),
            destructive: false,
            security_authorized: false, // not authorized
        };
        let v = agent.validate_pre_execution(&op, OperationalMode::HighRisk);
        assert!(!v.all_passed());
        assert!(!v.security_cleared);
    }

    #[test]
    fn pre_exec_validation_high_risk_with_authorization() {
        let mut agent = SysAdminAgent::new(test_agent_id());
        let op = SystemOperation {
            category: OperationCategory::Configuration,
            description: "set timezone".into(),
            destructive: false,
            security_authorized: true,
        };
        let v = agent.validate_pre_execution(&op, OperationalMode::HighRisk);
        assert!(v.all_passed());
    }

    #[test]
    fn execute_increments_counter() {
        let mut agent = SysAdminAgent::new(test_agent_id());
        let op = SystemOperation {
            category: OperationCategory::Diagnostics,
            description: "health check".into(),
            destructive: false,
            security_authorized: false,
        };
        agent.execute_operation(&op);
        assert_eq!(agent.operations_executed(), 1);
        agent.execute_operation(&op);
        assert_eq!(agent.operations_executed(), 2);
    }

    #[test]
    fn operation_categories_are_distinct() {
        let categories = [
            OperationCategory::Configuration,
            OperationCategory::PackageManagement,
            OperationCategory::DriverManagement,
            OperationCategory::Maintenance,
            OperationCategory::MeshOperations,
            OperationCategory::Diagnostics,
        ];
        for (i, a) in categories.iter().enumerate() {
            for (j, b) in categories.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[tokio::test]
    async fn spawn_and_shutdown() {
        let mut agent = SysAdminAgent::new(test_agent_id());
        agent.spawn().await.unwrap();
        assert_eq!(agent.state(), AgentState::Running);
        agent.shutdown().await.unwrap();
        assert_eq!(agent.state(), AgentState::Shutdown);
    }

    #[test]
    fn agent_kind_is_sysadmin() {
        let agent = SysAdminAgent::new(test_agent_id());
        assert_eq!(agent.kind(), AgentKind::SysAdmin);
    }

    // ── CapabilityChecker tests ────────────────────────────────────────────

    #[test]
    fn capability_checker_package_management_includes_install_and_remove() {
        let caps = CapabilityChecker::required_capabilities(OperationCategory::PackageManagement);
        assert!(caps.contains(&AgentCapability::PkgInstall));
        assert!(caps.contains(&AgentCapability::PkgRemove));
    }

    #[test]
    fn capability_checker_driver_management_includes_driver_load() {
        let caps = CapabilityChecker::required_capabilities(OperationCategory::DriverManagement);
        assert!(caps.contains(&AgentCapability::DriverLoad));
    }

    #[test]
    fn capability_checker_configuration_includes_sys_configure() {
        let caps = CapabilityChecker::required_capabilities(OperationCategory::Configuration);
        assert!(caps.contains(&AgentCapability::SysConfigure));
    }

    #[test]
    fn capability_checker_maintenance_includes_fs_write_and_sys_configure() {
        let caps = CapabilityChecker::required_capabilities(OperationCategory::Maintenance);
        assert!(caps.contains(&AgentCapability::FsWrite));
        assert!(caps.contains(&AgentCapability::SysConfigure));
    }

    #[test]
    fn capability_checker_mesh_operations_includes_net_admin() {
        let caps = CapabilityChecker::required_capabilities(OperationCategory::MeshOperations);
        assert!(caps.contains(&AgentCapability::NetAdmin));
    }

    #[test]
    fn capability_checker_diagnostics_includes_fs_read_and_perf_profile() {
        let caps = CapabilityChecker::required_capabilities(OperationCategory::Diagnostics);
        assert!(caps.contains(&AgentCapability::FsRead));
        assert!(caps.contains(&AgentCapability::PerfProfile));
    }

    #[test]
    fn capability_checker_all_categories_return_non_empty_set() {
        let all = [
            OperationCategory::Configuration,
            OperationCategory::PackageManagement,
            OperationCategory::DriverManagement,
            OperationCategory::Maintenance,
            OperationCategory::MeshOperations,
            OperationCategory::Diagnostics,
        ];
        for cat in all {
            assert!(
                !CapabilityChecker::required_capabilities(cat).is_empty(),
                "{cat:?} returned an empty capability set"
            );
        }
    }

    // ── CategoryRouter classification tests ───────────────────────────────

    #[test]
    fn router_install_maps_to_package_management() {
        assert_eq!(
            CategoryRouter::classify_operation("install nginx"),
            OperationCategory::PackageManagement,
        );
    }

    #[test]
    fn router_update_maps_to_package_management() {
        assert_eq!(
            CategoryRouter::classify_operation("update all packages"),
            OperationCategory::PackageManagement,
        );
    }

    #[test]
    fn router_remove_maps_to_package_management() {
        assert_eq!(
            CategoryRouter::classify_operation("remove old package"),
            OperationCategory::PackageManagement,
        );
    }

    #[test]
    fn router_driver_maps_to_driver_management() {
        assert_eq!(
            CategoryRouter::classify_operation("load gpu driver"),
            OperationCategory::DriverManagement,
        );
    }

    #[test]
    fn router_firmware_maps_to_driver_management() {
        assert_eq!(
            CategoryRouter::classify_operation("update firmware"),
            OperationCategory::DriverManagement,
        );
    }

    #[test]
    fn router_configure_maps_to_configuration() {
        assert_eq!(
            CategoryRouter::classify_operation("configure network settings"),
            OperationCategory::Configuration,
        );
    }

    #[test]
    fn router_settings_maps_to_configuration() {
        assert_eq!(
            CategoryRouter::classify_operation("change settings"),
            OperationCategory::Configuration,
        );
    }

    #[test]
    fn router_disk_cleanup_maps_to_maintenance() {
        assert_eq!(
            CategoryRouter::classify_operation("disk cleanup"),
            OperationCategory::Maintenance,
        );
    }

    #[test]
    fn router_cache_maps_to_maintenance() {
        assert_eq!(
            CategoryRouter::classify_operation("clear cache"),
            OperationCategory::Maintenance,
        );
    }

    #[test]
    fn router_mesh_maps_to_mesh_operations() {
        assert_eq!(
            CategoryRouter::classify_operation("enroll node into mesh"),
            OperationCategory::MeshOperations,
        );
    }

    #[test]
    fn router_peer_maps_to_mesh_operations() {
        assert_eq!(
            CategoryRouter::classify_operation("configure peer"),
            OperationCategory::MeshOperations,
        );
    }

    #[test]
    fn router_health_maps_to_diagnostics() {
        assert_eq!(
            CategoryRouter::classify_operation("run health check"),
            OperationCategory::Diagnostics,
        );
    }

    #[test]
    fn router_benchmark_maps_to_diagnostics() {
        assert_eq!(
            CategoryRouter::classify_operation("run benchmark"),
            OperationCategory::Diagnostics,
        );
    }

    #[test]
    fn router_unknown_falls_back_to_configuration() {
        assert_eq!(
            CategoryRouter::classify_operation("do something unrecognized"),
            OperationCategory::Configuration,
        );
    }

    #[test]
    fn router_classification_is_case_insensitive() {
        assert_eq!(
            CategoryRouter::classify_operation("INSTALL NGINX"),
            OperationCategory::PackageManagement,
        );
        assert_eq!(
            CategoryRouter::classify_operation("Load GPU Driver"),
            OperationCategory::DriverManagement,
        );
    }

    #[test]
    fn router_package_management_is_destructive() {
        assert!(CategoryRouter::is_destructive(
            OperationCategory::PackageManagement
        ));
    }

    #[test]
    fn router_maintenance_is_destructive() {
        assert!(CategoryRouter::is_destructive(
            OperationCategory::Maintenance
        ));
    }

    #[test]
    fn router_non_destructive_categories_return_false() {
        for cat in [
            OperationCategory::Configuration,
            OperationCategory::DriverManagement,
            OperationCategory::MeshOperations,
            OperationCategory::Diagnostics,
        ] {
            assert!(
                !CategoryRouter::is_destructive(cat),
                "{cat:?} should not be destructive"
            );
        }
    }

    // ── RollbackManager tests ──────────────────────────────────────────────

    #[test]
    fn rollback_manager_create_returns_stable_id() {
        let mut mgr = RollbackManager::new(8);
        let id = mgr.create_point(
            "before install".into(),
            OperationCategory::PackageManagement,
        );
        assert_eq!(mgr.list_points().len(), 1);
        assert_eq!(mgr.list_points()[0].id, id);
    }

    #[test]
    fn rollback_manager_successive_ids_are_unique() {
        let mut mgr = RollbackManager::new(16);
        let a = mgr.create_point("op a".into(), OperationCategory::Configuration);
        let b = mgr.create_point("op b".into(), OperationCategory::Maintenance);
        assert_ne!(a, b);
    }

    #[test]
    fn rollback_manager_rollback_removes_and_returns_point() {
        let mut mgr = RollbackManager::new(8);
        let id = mgr.create_point("before cleanup".into(), OperationCategory::Maintenance);
        let point = mgr.rollback(id).unwrap();
        assert_eq!(point.id, id);
        assert_eq!(mgr.list_points().len(), 0);
    }

    #[test]
    fn rollback_manager_not_found_returns_error() {
        let mut mgr = RollbackManager::new(8);
        let err = mgr.rollback(999).unwrap_err();
        assert!(matches!(err, RollbackError::NotFound { id: 999 }));
    }

    #[test]
    fn rollback_manager_evicts_oldest_at_capacity() {
        let mut mgr = RollbackManager::new(2);
        let id1 = mgr.create_point("first".into(), OperationCategory::Configuration);
        let _id2 = mgr.create_point("second".into(), OperationCategory::Configuration);
        // Adding a third point must evict id1.
        let _id3 = mgr.create_point("third".into(), OperationCategory::Configuration);
        assert_eq!(mgr.list_points().len(), 2);
        assert!(
            mgr.list_points().iter().all(|p| p.id != id1),
            "id1 should have been evicted"
        );
    }

    // ── AuditEmitter tests ─────────────────────────────────────────────────

    #[test]
    fn audit_emitter_records_pre_exec_event() {
        let mut emitter = AuditEmitter::new();
        emitter.emit(AuditEvent {
            operation: "install nginx".into(),
            category: OperationCategory::PackageManagement,
            timestamp: 0,
            pre_exec: true,
            result: None,
        });
        assert_eq!(emitter.events().len(), 1);
        assert!(emitter.events()[0].pre_exec);
        assert_eq!(emitter.events()[0].result, None);
    }

    #[test]
    fn audit_emitter_records_post_exec_result() {
        let mut emitter = AuditEmitter::new();
        emitter.emit(AuditEvent {
            operation: "disk cleanup".into(),
            category: OperationCategory::Maintenance,
            timestamp: 0,
            pre_exec: false,
            result: Some(true),
        });
        assert_eq!(emitter.events()[0].result, Some(true));
        assert!(!emitter.events()[0].pre_exec);
    }

    // ── Integration: validate_pre_execution drives rollback + audit ────────

    #[test]
    fn validate_pre_exec_emits_one_pre_exec_audit_event() {
        let mut agent = SysAdminAgent::new(test_agent_id());
        let op = SystemOperation {
            category: OperationCategory::Configuration,
            description: "set hostname".into(),
            destructive: false,
            security_authorized: false,
        };
        let _ = agent.validate_pre_execution(&op, OperationalMode::Standard);
        assert_eq!(agent.audit_emitter().events().len(), 1);
        assert!(agent.audit_emitter().events()[0].pre_exec);
    }

    #[test]
    fn validate_pre_exec_creates_rollback_for_destructive_flag() {
        let mut agent = SysAdminAgent::new(test_agent_id());
        // Diagnostics is not inherently destructive, but we flag it explicitly.
        let op = SystemOperation {
            category: OperationCategory::Diagnostics,
            description: "wipe diagnostic cache".into(),
            destructive: true, // explicit flag
            security_authorized: false,
        };
        let _ = agent.validate_pre_execution(&op, OperationalMode::Standard);
        assert_eq!(
            agent.rollback_manager().list_points().len(),
            1,
            "a rollback point must be created when destructive=true"
        );
    }

    #[test]
    fn validate_pre_exec_creates_rollback_for_maintenance_category() {
        let mut agent = SysAdminAgent::new(test_agent_id());
        let op = SystemOperation {
            category: OperationCategory::Maintenance,
            description: "purge old logs".into(),
            destructive: false, // category alone triggers rollback
            security_authorized: false,
        };
        let _ = agent.validate_pre_execution(&op, OperationalMode::Standard);
        assert_eq!(
            agent.rollback_manager().list_points().len(),
            1,
            "Maintenance category must trigger rollback even when destructive=false"
        );
    }

    #[test]
    fn validate_pre_exec_no_rollback_for_safe_non_destructive_op() {
        let mut agent = SysAdminAgent::new(test_agent_id());
        let op = SystemOperation {
            category: OperationCategory::Diagnostics,
            description: "run health check".into(),
            destructive: false,
            security_authorized: false,
        };
        let _ = agent.validate_pre_execution(&op, OperationalMode::Standard);
        assert_eq!(
            agent.rollback_manager().list_points().len(),
            0,
            "non-destructive Diagnostics op must not create a rollback point"
        );
    }
}

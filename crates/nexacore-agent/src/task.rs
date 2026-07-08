//! Task Agent — user-delegated productive work.
//!
//! Executes goal-oriented tasks on behalf of the user: research,
//! content creation, file/data management, background monitoring,
//! scheduling, and communication drafting. Operates on user data
//! and external resources; MUST NOT operate on system infrastructure.
//!
//! See NCIP-Agent-Arch-022 §S9.

use async_trait::async_trait;
use nexacore_types::{AgentId, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use crate::{
    agent::{Agent, AgentKind, AgentState},
    budget::Budget,
    message::{AgentMessage, MessageKind, MessagePayload, OperationResult},
};

// ── Task categories ────────────────────────────────────────────────────────────

/// Categories of tasks the Task Agent can perform (NCIP-022 §S9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskCategory {
    /// Web search, price comparison, paper search, market analysis.
    Research,
    /// Create presentations, reports, documents, translations.
    ContentCreation,
    /// Reorganize files, batch rename, deduplicate, extract data.
    FileManagement,
    /// Trip planning, meeting prep, calendar management.
    Scheduling,
    /// Draft emails, summarize conversations, prepare responses.
    CommunicationDraft,
    /// Price alerts, topic monitoring, deadline tracking.
    BackgroundMonitoring,
}

// ── Task status ────────────────────────────────────────────────────────────────

/// Status of a background task.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskStatus {
    /// Task is queued but not yet started.
    Pending,
    /// Task is actively executing.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled by the user.
    Cancelled,
    /// Task failed with an error.
    Failed,
}

// ── UserTask ──────────────────────────────────────────────────────────────────

/// A user-delegated task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserTask {
    /// Unique task identifier.
    pub task_id: u64,
    /// Category of the task.
    pub category: TaskCategory,
    /// Human-readable description of what to do.
    pub description: String,
    /// Current status.
    pub status: TaskStatus,
    /// Whether this task requires external network access.
    pub requires_egress: bool,
    /// Whether Security Agent has pre-authorized (required in High-Risk).
    pub security_authorized: bool,
    /// Progress percentage (0–100), if trackable.
    pub progress_percent: Option<u8>,
}

// ── BackgroundTask / BackgroundTaskRunner ──────────────────────────────────────

/// A single background task tracked by [`BackgroundTaskRunner`].
///
/// Stores all metadata needed to monitor, update, and cancel a long-running
/// task as specified by NCIP-022 §S9.3.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackgroundTask {
    /// Unique task identifier (assigned at submit time).
    pub task_id: u64,
    /// Human-readable description of the work.
    pub description: String,
    /// Current execution status.
    pub status: TaskStatus,
    /// Progress as a percentage (0–100).
    pub progress_percent: u8,
    /// Unix timestamp (seconds) when the task was submitted.
    ///
    /// Stubbed to `0` until the `nexacore-hal` Clock abstraction lands (Phase 6).
    pub created_at: u64,
    /// Unix timestamp (seconds) of the last status/progress update.
    ///
    /// Stubbed to `0` until the `nexacore-hal` Clock abstraction lands (Phase 6).
    pub updated_at: u64,
    /// Human-readable result string, populated when the task completes
    /// or is partially cancelled.
    pub result: Option<String>,
}

/// Manages background task execution with a bounded concurrency limit
/// (NCIP-022 §S9.3).
///
/// Tasks are created in `Running` state synchronously (real async dispatch
/// will be wired in a future sprint once the `nexacore-runtime` executor
/// surface is stable). Progress updates and cancellation are fully
/// supported now so the public API contract is established.
#[derive(Debug)]
pub struct BackgroundTaskRunner {
    /// All tasks ever submitted in this session (running, completed, cancelled).
    tasks: Vec<BackgroundTask>,
    /// Upper bound on the number of concurrently running tasks.
    max_concurrent: usize,
    /// Monotonically increasing counter used to assign unique task IDs.
    next_id: u64,
}

impl BackgroundTaskRunner {
    /// Create a new runner with the given concurrency limit.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_agent::task::BackgroundTaskRunner;
    ///
    /// let runner = BackgroundTaskRunner::new(4);
    /// assert_eq!(runner.running_count(), 0);
    /// ```
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            tasks: Vec::new(),
            max_concurrent,
            next_id: 1,
        }
    }

    /// Submit a new background task and return its assigned ID.
    ///
    /// The task is created in `Running` state when concurrency headroom
    /// is available, or `Pending` when the limit is already reached.
    pub fn submit(&mut self, description: String) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        // Determine initial status based on concurrency headroom.
        let status = if self.running_count() < self.max_concurrent {
            TaskStatus::Running
        } else {
            TaskStatus::Pending
        };

        info!(task_id = id, %description, ?status, "background task submitted");

        self.tasks.push(BackgroundTask {
            task_id: id,
            description,
            status,
            progress_percent: 0,
            created_at: 0, // stub: real clock in Phase 6
            updated_at: 0, // stub: real clock in Phase 6
            result: None,
        });
        id
    }

    /// Update the progress percentage for a running task.
    ///
    /// Returns `true` when the task was found and updated.
    /// Returns `false` when no task with `task_id` exists.
    ///
    /// The value is clamped to `100`; task completion is not automatic —
    /// callers must transition the status to `Completed` separately.
    pub fn update_progress(&mut self, task_id: u64, percent: u8) -> bool {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.task_id == task_id) {
            task.progress_percent = percent.min(100);
            task.updated_at = 0; // stub: real clock in Phase 6
            debug!(
                task_id,
                progress = task.progress_percent,
                "task progress updated"
            );
            true
        } else {
            false
        }
    }

    /// Cancel a task, preserving any partial results (NCIP-022 §S9.3).
    ///
    /// Sets the task status to `Cancelled`, attaches a partial-result
    /// message derived from the current progress, and returns a clone of
    /// the cancelled task. Returns `None` if no task with `task_id` exists.
    pub fn cancel(&mut self, task_id: u64) -> Option<BackgroundTask> {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.task_id == task_id) {
            task.status = TaskStatus::Cancelled;
            // Preserve whatever partial progress was made.
            if task.result.is_none() {
                task.result = Some(format!("cancelled at {}% progress", task.progress_percent));
            }
            task.updated_at = 0; // stub: real clock in Phase 6
            info!(
                task_id,
                "background task cancelled, partial results preserved"
            );
            Some(task.clone())
        } else {
            None
        }
    }

    /// Returns the task with the given ID, or `None` if not found.
    #[must_use]
    pub fn get_status(&self, task_id: u64) -> Option<&BackgroundTask> {
        self.tasks.iter().find(|t| t.task_id == task_id)
    }

    /// Returns the number of tasks currently in `Running` state.
    #[must_use]
    pub fn running_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Running)
            .count()
    }

    /// Returns all tasks that have reached a terminal state
    /// (`Completed`, `Cancelled`, or `Failed`).
    #[must_use]
    pub fn completed_tasks(&self) -> Vec<&BackgroundTask> {
        self.tasks
            .iter()
            .filter(|t| {
                matches!(
                    t.status,
                    TaskStatus::Completed | TaskStatus::Cancelled | TaskStatus::Failed
                )
            })
            .collect()
    }
}

// ── FilesystemScope ────────────────────────────────────────────────────────────

/// Error returned when a filesystem path violates the Task Agent's scope
/// (NCIP-022 §S9.2).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FilescopeViolation {
    /// The path targets a system directory the Task Agent must never access.
    #[error("path '{path}' is a system path and cannot be accessed by the Task Agent")]
    SystemPath {
        /// The rejected path.
        path: String,
    },
    /// The path matches an explicitly denied prefix.
    #[error("path '{path}' matches denied prefix '{prefix}'")]
    DeniedPrefix {
        /// The rejected path.
        path: String,
        /// The denied prefix that matched.
        prefix: String,
    },
}

/// Enforces filesystem access boundaries for the Task Agent
/// (NCIP-022 §S9.2).
///
/// The Task Agent's `fs:write` capability is scoped to user data paths.
/// Any attempt to access system paths must be rejected before the operation
/// reaches the capability system.
///
/// # Access resolution order
///
/// 1. Check `denied_prefixes` — if any match, return [`FilescopeViolation::DeniedPrefix`].
/// 2. Check `allowed_prefixes` — if none match, return [`FilescopeViolation::SystemPath`].
/// 3. Allow.
#[derive(Debug)]
pub struct FilesystemScope {
    /// Path prefixes the Task Agent is permitted to access.
    allowed_prefixes: Vec<String>,
    /// Path prefixes that are explicitly denied, regardless of the allowed set.
    denied_prefixes: Vec<String>,
}

impl FilesystemScope {
    /// Create a scope with the default user-data boundaries.
    ///
    /// Allowed:  `/home/`
    /// Denied:   `/system/`, `/etc/`, `/drivers/`, `/boot/`
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_agent::task::FilesystemScope;
    ///
    /// let scope = FilesystemScope::new_user_scope();
    /// assert!(scope.is_allowed("/home/user/documents/report.pdf"));
    /// assert!(!scope.is_allowed("/etc/passwd"));
    /// ```
    #[must_use]
    pub fn new_user_scope() -> Self {
        Self {
            allowed_prefixes: vec!["/home/".to_string()],
            denied_prefixes: vec![
                "/system/".to_string(),
                "/etc/".to_string(),
                "/drivers/".to_string(),
                "/boot/".to_string(),
            ],
        }
    }

    /// Returns `true` if `path` is within the allowed scope and not denied.
    #[must_use]
    pub fn is_allowed(&self, path: &str) -> bool {
        // Denied prefix check takes priority over allowed prefixes.
        if self
            .denied_prefixes
            .iter()
            .any(|p| path.starts_with(p.as_str()))
        {
            return false;
        }
        self.allowed_prefixes
            .iter()
            .any(|p| path.starts_with(p.as_str()))
    }

    /// Validate a write operation to `path`.
    ///
    /// # Errors
    ///
    /// Returns [`FilescopeViolation::DeniedPrefix`] when the path matches a
    /// denied prefix, or [`FilescopeViolation::SystemPath`] when the path falls
    /// outside all allowed prefixes.
    pub fn validate_write(&self, path: &str) -> core::result::Result<(), FilescopeViolation> {
        self.validate_access(path)
    }

    /// Validate a read operation on `path`.
    ///
    /// # Errors
    ///
    /// Returns [`FilescopeViolation::DeniedPrefix`] when the path matches a
    /// denied prefix, or [`FilescopeViolation::SystemPath`] when the path falls
    /// outside all allowed prefixes.
    pub fn validate_read(&self, path: &str) -> core::result::Result<(), FilescopeViolation> {
        self.validate_access(path)
    }

    /// Internal shared access check for reads and writes.
    ///
    /// Evaluates denied prefixes before allowed prefixes so that a denied
    /// prefix always wins, preventing a crafted allowed prefix from
    /// accidentally permitting a denied path.
    fn validate_access(&self, path: &str) -> core::result::Result<(), FilescopeViolation> {
        for denied in &self.denied_prefixes {
            if path.starts_with(denied.as_str()) {
                warn!(path, denied_prefix = %denied, "filesystem scope violation: denied prefix");
                return Err(FilescopeViolation::DeniedPrefix {
                    path: path.to_string(),
                    prefix: denied.clone(),
                });
            }
        }

        if !self
            .allowed_prefixes
            .iter()
            .any(|p| path.starts_with(p.as_str()))
        {
            warn!(path, "filesystem scope violation: system path");
            return Err(FilescopeViolation::SystemPath {
                path: path.to_string(),
            });
        }

        Ok(())
    }
}

// ── ExternalAccessControl ─────────────────────────────────────────────────────

/// A single entry in the external access log (NCIP-022 §S9.4 ¶4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalAccessEntry {
    /// The target URL or API endpoint.
    pub url: String,
    /// The outgoing query with PII stripped via `nexacore-tokenization`.
    ///
    /// This sprint stores the value as supplied; real PII tokenization will be
    /// wired once `nexacore-tokenization` exposes a stable synchronous API.
    pub query_tokenized: String,
    /// Size of the response body in bytes.
    pub response_size: u64,
    /// Unix timestamp (seconds) of the request.
    ///
    /// Stubbed to `0` until the `nexacore-hal` Clock abstraction lands (Phase 6).
    pub timestamp: u64,
}

/// Error returned when no further external requests are allowed because
/// the privacy budget is exhausted (NCIP-022 §S9.4 ¶2).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("privacy budget exhausted: no more external requests are allowed until budget is reset")]
pub struct PrivacyBudgetExhausted;

/// Tracks and rate-limits external access by the Task Agent
/// (NCIP-022 §S9.4).
///
/// Every external request (web search, API call) must be logged here and
/// charged against a privacy budget. When the budget reaches zero,
/// [`log_request`](ExternalAccessControl::log_request) returns
/// [`PrivacyBudgetExhausted`] and the caller must stop making external
/// requests until the budget is reset.
///
/// Cost model: fixed unit cost of 1 per request. The per-request cost
/// formula from `docs/04-security-model.md` § Privacy budget is deferred
/// to a future sprint pending the full PII-sensitivity classification.
#[derive(Debug)]
pub struct ExternalAccessControl {
    /// Append-only log of all external requests made in this session.
    requests_log: Vec<ExternalAccessEntry>,
    /// Remaining privacy budget (units).
    privacy_budget_remaining: u64,
    /// Maximum budget value restored by `reset_budget`.
    privacy_budget_max: u64,
}

impl ExternalAccessControl {
    /// Create a new controller with the given maximum privacy budget.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_agent::task::ExternalAccessControl;
    ///
    /// let ctrl = ExternalAccessControl::new(100);
    /// assert_eq!(ctrl.budget_remaining(), 100);
    /// assert_eq!(ctrl.request_count(), 0);
    /// ```
    #[must_use]
    pub fn new(budget: u64) -> Self {
        Self {
            requests_log: Vec::new(),
            privacy_budget_remaining: budget,
            privacy_budget_max: budget,
        }
    }

    /// Log an external request and deduct one unit from the privacy budget.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyBudgetExhausted`] when the budget is already zero.
    /// The entry is NOT logged and the request MUST NOT proceed.
    pub fn log_request(
        &mut self,
        entry: ExternalAccessEntry,
    ) -> core::result::Result<(), PrivacyBudgetExhausted> {
        if self.privacy_budget_remaining == 0 {
            warn!(url = %entry.url, "external request blocked: privacy budget exhausted");
            return Err(PrivacyBudgetExhausted);
        }

        self.privacy_budget_remaining -= 1;
        info!(
            url = %entry.url,
            budget_remaining = self.privacy_budget_remaining,
            "external request logged"
        );
        self.requests_log.push(entry);
        Ok(())
    }

    /// Returns the remaining privacy budget (units).
    #[must_use]
    pub fn budget_remaining(&self) -> u64 {
        self.privacy_budget_remaining
    }

    /// Reset the privacy budget to its maximum value.
    ///
    /// The request log is NOT cleared — it is append-only for audit purposes.
    /// This method is intended for use at the start of a new time window.
    pub fn reset_budget(&mut self) {
        self.privacy_budget_remaining = self.privacy_budget_max;
        info!(budget = self.privacy_budget_max, "privacy budget reset");
    }

    /// Returns the total number of external requests logged in this session.
    #[must_use]
    pub fn request_count(&self) -> usize {
        self.requests_log.len()
    }
}

// ── TaskAgent ─────────────────────────────────────────────────────────────────

/// The Task Agent.
///
/// Executes user-delegated productive work. Operates on user data
/// paths and external resources. MUST NOT touch system infrastructure
/// (NCIP-022 §S9).
pub struct TaskAgent {
    id: AgentId,
    state: AgentState,
    #[allow(dead_code)] // enforced in a later sprint
    budget: Budget,
    tasks_executed: u64,
    active_tasks: Vec<UserTask>,
    /// Manages long-running background tasks (NCIP-022 §S9.3).
    task_runner: BackgroundTaskRunner,
    /// Enforces filesystem access scope (NCIP-022 §S9.2).
    filesystem_scope: FilesystemScope,
    /// Tracks and rate-limits external network access (NCIP-022 §S9.4).
    access_control: ExternalAccessControl,
    /// Optional transport to the AI runtime (TASK-13 / ADR-0035 D2).
    ///
    /// `None` (the default) preserves the pre-TASK-13 behaviour exactly:
    /// intents are summarised synthetically.  When present, intents that
    /// require generative reasoning are served by the runtime and the
    /// operation result carries the REAL model answer.
    runtime_link: Option<std::sync::Arc<dyn crate::runtime_link::RuntimeLink>>,
}

impl std::fmt::Debug for TaskAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskAgent")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("tasks_executed", &self.tasks_executed)
            .field("active_tasks", &self.active_tasks.len())
            .field("runtime_link", &self.runtime_link.is_some())
            .finish_non_exhaustive()
    }
}

impl TaskAgent {
    /// Create a new Task agent.
    #[must_use]
    pub fn new(id: AgentId) -> Self {
        Self {
            id,
            state: AgentState::Initializing,
            budget: Budget::task_default(),
            tasks_executed: 0,
            active_tasks: Vec::new(),
            task_runner: BackgroundTaskRunner::new(8),
            filesystem_scope: FilesystemScope::new_user_scope(),
            access_control: ExternalAccessControl::new(1_000),
            runtime_link: None,
        }
    }

    /// Attach a [`RuntimeLink`](crate::runtime_link::RuntimeLink) (builder
    /// style) so inference-class intents are served by the AI runtime
    /// (TASK-13 / ADR-0035 D2).
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::sync::Arc;
    ///
    /// use async_trait::async_trait;
    /// use nexacore_agent::{
    ///     runtime_link::{RuntimeLink, RuntimeLinkError},
    ///     task::TaskAgent,
    /// };
    /// use nexacore_types::AgentId;
    ///
    /// struct FixedLink;
    /// #[async_trait]
    /// impl RuntimeLink for FixedLink {
    ///     async fn infer(&self, p: &str, _rid: u64) -> Result<String, RuntimeLinkError> {
    ///         Ok(format!("echo: {p}"))
    ///     }
    /// }
    ///
    /// let agent = TaskAgent::new(AgentId::new()).with_runtime_link(Arc::new(FixedLink));
    /// ```
    #[must_use]
    pub fn with_runtime_link(
        mut self,
        link: std::sync::Arc<dyn crate::runtime_link::RuntimeLink>,
    ) -> Self {
        self.runtime_link = Some(link);
        self
    }

    /// Returns the total number of tasks executed in this session.
    #[must_use]
    pub fn tasks_executed(&self) -> u64 {
        self.tasks_executed
    }

    /// Returns the number of currently active tasks.
    #[must_use]
    pub fn active_task_count(&self) -> usize {
        self.active_tasks.len()
    }

    /// Returns a reference to the background task runner for inspection.
    #[must_use]
    pub fn task_runner(&self) -> &BackgroundTaskRunner {
        &self.task_runner
    }

    /// Returns a reference to the filesystem scope enforcer for inspection.
    #[must_use]
    pub fn filesystem_scope(&self) -> &FilesystemScope {
        &self.filesystem_scope
    }

    /// Returns a reference to the external access controller for inspection.
    #[must_use]
    pub fn access_control(&self) -> &ExternalAccessControl {
        &self.access_control
    }

    /// Classify an intent description into a task category.
    ///
    /// Keyword-based heuristics; first match wins (top to bottom).
    #[must_use]
    pub fn classify_task(description: &str) -> TaskCategory {
        let lower = description.to_lowercase();

        if lower.contains("search")
            || lower.contains("find")
            || lower.contains("compare")
            || lower.contains("cerca")
            || lower.contains("trovami")
            || lower.contains("confronta")
        {
            return TaskCategory::Research;
        }

        if lower.contains("create")
            || lower.contains("generate")
            || lower.contains("draft")
            || lower.contains("presentation")
            || lower.contains("report")
            || lower.contains("crea")
            || lower.contains("presentazione")
        {
            return TaskCategory::ContentCreation;
        }

        if lower.contains("organize")
            || lower.contains("rename")
            || lower.contains("move files")
            || lower.contains("deduplicate")
            || lower.contains("riorganizza")
            || lower.contains("rinomina")
        {
            return TaskCategory::FileManagement;
        }

        if lower.contains("schedule")
            || lower.contains("plan")
            || lower.contains("calendar")
            || lower.contains("pianifica")
            || lower.contains("viaggio")
        {
            return TaskCategory::Scheduling;
        }

        if lower.contains("email")
            || lower.contains("reply")
            || lower.contains("summarize conversation")
            || lower.contains("rispondi")
        {
            return TaskCategory::CommunicationDraft;
        }

        if lower.contains("monitor")
            || lower.contains("alert")
            || lower.contains("watch")
            || lower.contains("track")
            || lower.contains("avvisami")
        {
            return TaskCategory::BackgroundMonitoring;
        }

        TaskCategory::Research
    }

    /// Returns whether a task category requires network egress.
    #[must_use]
    pub fn requires_egress(category: TaskCategory) -> bool {
        matches!(
            category,
            TaskCategory::Research | TaskCategory::BackgroundMonitoring
        )
    }

    /// Submit a new task for execution.
    fn submit_task(&mut self, description: &str) -> usize {
        let category = Self::classify_task(description);
        self.tasks_executed += 1;
        let task = UserTask {
            task_id: self.tasks_executed,
            category,
            description: description.to_string(),
            status: TaskStatus::Running,
            requires_egress: Self::requires_egress(category),
            security_authorized: false,
            progress_percent: Some(0),
        };
        self.active_tasks.push(task);
        self.active_tasks.len() - 1
    }

    /// Cancel an active task by ID.
    pub fn cancel_task(&mut self, task_id: u64) -> bool {
        if let Some(task) = self.active_tasks.iter_mut().find(|t| t.task_id == task_id) {
            task.status = TaskStatus::Cancelled;
            true
        } else {
            false
        }
    }
}

#[async_trait]
impl Agent for TaskAgent {
    fn kind(&self) -> AgentKind {
        AgentKind::Task
    }

    fn id(&self) -> AgentId {
        self.id
    }

    fn state(&self) -> AgentState {
        self.state
    }

    #[instrument(skip(self), fields(agent = "task"))]
    async fn spawn(&mut self) -> Result<()> {
        info!("task agent spawning");
        self.state = AgentState::Running;
        Ok(())
    }

    #[instrument(skip(self, message), fields(agent = "task", msg_kind = ?message.kind))]
    async fn handle_message(&mut self, message: AgentMessage) -> Result<AgentMessage> {
        debug!(from = ?message.from, "processing message");

        let response_payload = match &message.payload {
            MessagePayload::Intent(intent) => {
                // For file-management intents, enforce filesystem scope on any
                // absolute path token found in the description. This is a
                // lightweight heuristic; full path extraction requires the
                // intent parser (planned for a future sprint).
                let category = Self::classify_task(&intent.content);
                if category == TaskCategory::FileManagement {
                    let path_token = intent
                        .content
                        .split_whitespace()
                        .find(|w| w.starts_with('/'));

                    if let Some(path) = path_token {
                        if let Err(violation) = self.filesystem_scope.validate_write(path) {
                            warn!(
                                request_id = intent.request_id,
                                path,
                                error = %violation,
                                "filesystem scope violation in task intent"
                            );
                            return Ok(AgentMessage {
                                id: message.id,
                                from: self.id,
                                to: message.from,
                                timestamp: message.timestamp,
                                kind: MessageKind::Result,
                                payload: MessagePayload::OperationResult(OperationResult {
                                    request_id: intent.request_id,
                                    success: false,
                                    summary: format!("filesystem scope violation: {violation}"),
                                }),
                                capabilities: vec![],
                                mode: message.mode,
                            });
                        }
                    }
                }

                let idx = self.submit_task(&intent.content);

                // TASK-13 (ADR-0035 D2): when a runtime link is attached
                // and the intent calls for generative reasoning, the
                // result carries the REAL model answer.  Without a link
                // (or for non-inference intents) the pre-TASK-13
                // synthetic summary is preserved byte-for-byte.
                let wants_inference =
                    nexacore_runtime::orchestrator_bridge::OrchestratorBridge::requires_inference(
                        &intent.content,
                    );
                if let (Some(link), true) = (self.runtime_link.as_ref(), wants_inference) {
                    match link.infer(&intent.content, intent.request_id).await {
                        Ok(answer) => MessagePayload::OperationResult(OperationResult {
                            request_id: intent.request_id,
                            success: true,
                            summary: answer,
                        }),
                        Err(e) => MessagePayload::OperationResult(OperationResult {
                            request_id: intent.request_id,
                            success: false,
                            summary: format!("runtime inference failed: {e}"),
                        }),
                    }
                } else {
                    let task = &self.active_tasks[idx];
                    let summary = format!(
                        "{:?}: {} (egress: {})",
                        task.category, task.description, task.requires_egress
                    );
                    MessagePayload::OperationResult(OperationResult {
                        request_id: intent.request_id,
                        success: true,
                        summary,
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
            tasks_executed = self.tasks_executed,
            active = self.active_tasks.len(),
            "task agent shutting down"
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
        AgentId::from_bytes([0x05; 16])
    }

    // ── Existing tests (preserved unchanged) ──────────────────────────────

    #[test]
    fn classify_research() {
        assert_eq!(
            TaskAgent::classify_task("find me a laptop with 32GB RAM"),
            TaskCategory::Research
        );
        assert_eq!(
            TaskAgent::classify_task("cerca un volo per Roma"),
            TaskCategory::Research
        );
    }

    #[test]
    fn classify_content_creation() {
        assert_eq!(
            TaskAgent::classify_task("create a presentation about AI"),
            TaskCategory::ContentCreation
        );
        assert_eq!(
            TaskAgent::classify_task("crea un report trimestrale"),
            TaskCategory::ContentCreation
        );
    }

    #[test]
    fn classify_file_management() {
        assert_eq!(
            TaskAgent::classify_task("organize my photos by date"),
            TaskCategory::FileManagement
        );
        assert_eq!(
            TaskAgent::classify_task("riorganizza i documenti"),
            TaskCategory::FileManagement
        );
    }

    #[test]
    fn classify_scheduling() {
        assert_eq!(
            TaskAgent::classify_task("plan a trip to Tokyo"),
            TaskCategory::Scheduling
        );
    }

    #[test]
    fn classify_communication() {
        assert_eq!(
            TaskAgent::classify_task("reply to the team email"),
            TaskCategory::CommunicationDraft
        );
    }

    #[test]
    fn classify_monitoring() {
        assert_eq!(
            TaskAgent::classify_task("alert me when the price drops"),
            TaskCategory::BackgroundMonitoring
        );
    }

    #[test]
    fn research_requires_egress() {
        assert!(TaskAgent::requires_egress(TaskCategory::Research));
        assert!(TaskAgent::requires_egress(
            TaskCategory::BackgroundMonitoring
        ));
    }

    #[test]
    fn file_management_no_egress() {
        assert!(!TaskAgent::requires_egress(TaskCategory::FileManagement));
        assert!(!TaskAgent::requires_egress(TaskCategory::ContentCreation));
    }

    #[test]
    fn submit_task_increments_counter() {
        let mut agent = TaskAgent::new(test_agent_id());
        agent.submit_task("find laptops");
        assert_eq!(agent.tasks_executed(), 1);
        assert_eq!(agent.active_task_count(), 1);
        agent.submit_task("create report");
        assert_eq!(agent.tasks_executed(), 2);
    }

    #[test]
    fn cancel_task() {
        let mut agent = TaskAgent::new(test_agent_id());
        agent.submit_task("monitor prices");
        assert!(agent.cancel_task(1));
        assert_eq!(agent.active_tasks[0].status, TaskStatus::Cancelled);
    }

    #[test]
    fn cancel_nonexistent_task_returns_false() {
        let mut agent = TaskAgent::new(test_agent_id());
        assert!(!agent.cancel_task(999));
    }

    #[tokio::test]
    async fn spawn_and_shutdown() {
        let mut agent = TaskAgent::new(test_agent_id());
        agent.spawn().await.unwrap();
        assert_eq!(agent.state(), AgentState::Running);
        agent.shutdown().await.unwrap();
        assert_eq!(agent.state(), AgentState::Shutdown);
    }

    #[test]
    fn agent_kind_is_task() {
        let agent = TaskAgent::new(test_agent_id());
        assert_eq!(agent.kind(), AgentKind::Task);
    }

    // ── BackgroundTaskRunner tests ─────────────────────────────────────────

    #[test]
    fn background_runner_submit_returns_stable_id() {
        let mut runner = BackgroundTaskRunner::new(4);
        let id = runner.submit("search for flights".into());
        assert_eq!(runner.get_status(id).unwrap().task_id, id);
    }

    #[test]
    fn background_runner_successive_ids_are_unique() {
        let mut runner = BackgroundTaskRunner::new(4);
        let a = runner.submit("task a".into());
        let b = runner.submit("task b".into());
        assert_ne!(a, b);
    }

    #[test]
    fn background_runner_running_count_increments() {
        let mut runner = BackgroundTaskRunner::new(4);
        assert_eq!(runner.running_count(), 0);
        runner.submit("task a".into());
        assert_eq!(runner.running_count(), 1);
        runner.submit("task b".into());
        assert_eq!(runner.running_count(), 2);
    }

    #[test]
    fn background_runner_task_is_pending_when_at_concurrency_limit() {
        let mut runner = BackgroundTaskRunner::new(1);
        runner.submit("task a".into()); // fills the only slot
        let id2 = runner.submit("task b".into()); // must be Pending
        assert_eq!(
            runner.get_status(id2).unwrap().status,
            TaskStatus::Pending,
            "second task should be Pending when concurrency limit is reached"
        );
    }

    #[test]
    fn background_runner_update_progress_returns_true_on_success() {
        let mut runner = BackgroundTaskRunner::new(4);
        let id = runner.submit("compile report".into());
        assert!(runner.update_progress(id, 50));
        assert_eq!(runner.get_status(id).unwrap().progress_percent, 50);
    }

    #[test]
    fn background_runner_update_progress_clamps_to_100() {
        let mut runner = BackgroundTaskRunner::new(4);
        let id = runner.submit("compile report".into());
        runner.update_progress(id, 200); // must clamp to 100
        assert_eq!(runner.get_status(id).unwrap().progress_percent, 100);
    }

    #[test]
    fn background_runner_update_progress_returns_false_for_unknown_id() {
        let mut runner = BackgroundTaskRunner::new(4);
        assert!(!runner.update_progress(999, 50));
    }

    #[test]
    fn background_runner_cancel_preserves_partial_results() {
        let mut runner = BackgroundTaskRunner::new(4);
        let id = runner.submit("monitor prices".into());
        runner.update_progress(id, 42);
        let cancelled = runner.cancel(id).unwrap();
        assert_eq!(cancelled.status, TaskStatus::Cancelled);
        assert!(
            cancelled.result.is_some(),
            "cancelled task must carry a partial-result message"
        );
        assert!(
            cancelled.result.as_ref().unwrap().contains("42"),
            "partial result should mention the progress percentage"
        );
    }

    #[test]
    fn background_runner_cancel_nonexistent_returns_none() {
        let mut runner = BackgroundTaskRunner::new(4);
        assert!(runner.cancel(999).is_none());
    }

    #[test]
    fn background_runner_completed_tasks_includes_cancelled() {
        let mut runner = BackgroundTaskRunner::new(4);
        let id = runner.submit("a task".into());
        runner.cancel(id);
        assert_eq!(runner.completed_tasks().len(), 1);
    }

    #[test]
    fn background_runner_completed_tasks_excludes_running() {
        let mut runner = BackgroundTaskRunner::new(4);
        runner.submit("running task".into());
        assert_eq!(runner.completed_tasks().len(), 0);
    }

    // ── FilesystemScope tests ──────────────────────────────────────────────

    #[test]
    fn filesystem_scope_allows_home_paths() {
        let scope = FilesystemScope::new_user_scope();
        assert!(scope.is_allowed("/home/user/documents/report.pdf"));
        assert!(scope.is_allowed("/home/alice/photos/vacation.jpg"));
    }

    #[test]
    fn filesystem_scope_denies_etc() {
        let scope = FilesystemScope::new_user_scope();
        assert!(!scope.is_allowed("/etc/passwd"));
        assert!(!scope.is_allowed("/etc/ssh/sshd_config"));
    }

    #[test]
    fn filesystem_scope_denies_boot() {
        let scope = FilesystemScope::new_user_scope();
        assert!(!scope.is_allowed("/boot/vmlinuz"));
    }

    #[test]
    fn filesystem_scope_denies_system() {
        let scope = FilesystemScope::new_user_scope();
        assert!(!scope.is_allowed("/system/lib/libc.so"));
    }

    #[test]
    fn filesystem_scope_denies_drivers() {
        let scope = FilesystemScope::new_user_scope();
        assert!(!scope.is_allowed("/drivers/gpu/nvidia.ko"));
    }

    #[test]
    fn filesystem_scope_denies_arbitrary_root_paths() {
        let scope = FilesystemScope::new_user_scope();
        assert!(!scope.is_allowed("/var/log/syslog"));
        assert!(!scope.is_allowed("/usr/bin/ls"));
    }

    #[test]
    fn filesystem_scope_validate_write_ok_for_user_path() {
        let scope = FilesystemScope::new_user_scope();
        assert!(scope.validate_write("/home/user/file.txt").is_ok());
    }

    #[test]
    fn filesystem_scope_validate_write_err_denied_prefix() {
        let scope = FilesystemScope::new_user_scope();
        let err = scope.validate_write("/etc/cron.d/malicious").unwrap_err();
        assert!(matches!(err, FilescopeViolation::DeniedPrefix { .. }));
    }

    #[test]
    fn filesystem_scope_validate_read_ok_for_user_path() {
        let scope = FilesystemScope::new_user_scope();
        assert!(scope.validate_read("/home/user/notes.txt").is_ok());
    }

    #[test]
    fn filesystem_scope_validate_read_err_system_path() {
        let scope = FilesystemScope::new_user_scope();
        let err = scope.validate_read("/var/run/something").unwrap_err();
        assert!(matches!(err, FilescopeViolation::SystemPath { .. }));
    }

    // ── ExternalAccessControl tests ────────────────────────────────────────

    #[test]
    fn access_control_starts_at_full_budget() {
        let ctrl = ExternalAccessControl::new(10);
        assert_eq!(ctrl.budget_remaining(), 10);
    }

    #[test]
    fn access_control_log_request_decrements_budget_and_increments_count() {
        let mut ctrl = ExternalAccessControl::new(10);
        ctrl.log_request(ExternalAccessEntry {
            url: "https://example.com/search".into(),
            query_tokenized: "laptop <TOKEN_BRAND>".into(),
            response_size: 4096,
            timestamp: 0,
        })
        .unwrap();
        assert_eq!(ctrl.budget_remaining(), 9);
        assert_eq!(ctrl.request_count(), 1);
    }

    #[test]
    fn access_control_blocks_request_when_budget_exhausted() {
        let mut ctrl = ExternalAccessControl::new(1);
        ctrl.log_request(ExternalAccessEntry {
            url: "https://example.com/a".into(),
            query_tokenized: "query a".into(),
            response_size: 0,
            timestamp: 0,
        })
        .unwrap();
        // Budget is now 0.
        let err = ctrl
            .log_request(ExternalAccessEntry {
                url: "https://example.com/b".into(),
                query_tokenized: "query b".into(),
                response_size: 0,
                timestamp: 0,
            })
            .unwrap_err();
        assert_eq!(err, PrivacyBudgetExhausted);
        // Only the first request was logged.
        assert_eq!(ctrl.request_count(), 1);
    }

    #[test]
    fn access_control_reset_restores_budget_but_preserves_log() {
        let mut ctrl = ExternalAccessControl::new(5);
        for _ in 0..5 {
            ctrl.log_request(ExternalAccessEntry {
                url: "https://example.com".into(),
                query_tokenized: "q".into(),
                response_size: 0,
                timestamp: 0,
            })
            .unwrap();
        }
        assert_eq!(ctrl.budget_remaining(), 0);
        ctrl.reset_budget();
        assert_eq!(ctrl.budget_remaining(), 5);
        // Log is NOT cleared — it is append-only for audit purposes.
        assert_eq!(ctrl.request_count(), 5);
    }

    #[test]
    fn access_control_request_count_reflects_logged_entries() {
        let mut ctrl = ExternalAccessControl::new(100);
        assert_eq!(ctrl.request_count(), 0);
        ctrl.log_request(ExternalAccessEntry {
            url: "https://api.example.com/data".into(),
            query_tokenized: "term".into(),
            response_size: 256,
            timestamp: 0,
        })
        .unwrap();
        assert_eq!(ctrl.request_count(), 1);
    }

    #[test]
    fn access_control_zero_budget_blocks_immediately() {
        let mut ctrl = ExternalAccessControl::new(0);
        let err = ctrl
            .log_request(ExternalAccessEntry {
                url: "https://example.com".into(),
                query_tokenized: "q".into(),
                response_size: 0,
                timestamp: 0,
            })
            .unwrap_err();
        assert_eq!(err, PrivacyBudgetExhausted);
        assert_eq!(ctrl.request_count(), 0);
    }
    // ---- RuntimeLink wiring (TASK-13 / ADR-0035 D2) -------------------------

    use crate::{
        message::{IntentClass, IntentPayload},
        mode::OperationalMode,
        runtime_link::{RuntimeLink, RuntimeLinkError},
    };

    /// Fixed-reply [`RuntimeLink`] mock for the seam tests.
    struct FixedLink;

    #[async_trait::async_trait]
    impl RuntimeLink for FixedLink {
        async fn infer(
            &self,
            prompt: &str,
            _request_id: u64,
        ) -> core::result::Result<String, RuntimeLinkError> {
            Ok(format!("ANSWER:{prompt}"))
        }
    }

    /// Always-failing link: the failure must fold into a clean
    /// `success = false` result, never a panic.
    struct FailingLink;

    #[async_trait::async_trait]
    impl RuntimeLink for FailingLink {
        async fn infer(
            &self,
            _prompt: &str,
            _request_id: u64,
        ) -> core::result::Result<String, RuntimeLinkError> {
            Err(RuntimeLinkError::Inference("backend down".to_owned()))
        }
    }

    fn intent_message(content: &str) -> AgentMessage {
        AgentMessage {
            id: crate::message::MessageId::from_raw(1),
            from: test_agent_id(),
            to: test_agent_id(),
            timestamp: 0,
            kind: MessageKind::Dispatch,
            payload: MessagePayload::Intent(IntentPayload {
                classification: IntentClass::Task,
                content: content.to_owned(),
                request_id: 42,
            }),
            capabilities: vec![],
            mode: OperationalMode::Standard,
        }
    }

    #[tokio::test]
    async fn inference_intent_with_link_returns_model_answer() {
        let mut agent =
            TaskAgent::new(test_agent_id()).with_runtime_link(std::sync::Arc::new(FixedLink));
        agent.spawn().await.unwrap();

        // "explain" is an INFERENCE_KEYWORDS member → routed to the link.
        let reply = agent
            .handle_message(intent_message("explain the boot sequence"))
            .await
            .unwrap();
        match reply.payload {
            MessagePayload::OperationResult(r) => {
                assert!(r.success);
                assert_eq!(r.summary, "ANSWER:explain the boot sequence");
                assert_eq!(r.request_id, 42);
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_inference_intent_keeps_synthetic_summary_even_with_link() {
        let mut agent =
            TaskAgent::new(test_agent_id()).with_runtime_link(std::sync::Arc::new(FixedLink));
        agent.spawn().await.unwrap();

        // No inference keyword → the pre-TASK-13 synthetic summary path.
        let reply = agent
            .handle_message(intent_message("install firefox"))
            .await
            .unwrap();
        match reply.payload {
            MessagePayload::OperationResult(r) => {
                assert!(r.success);
                assert!(
                    !r.summary.starts_with("ANSWER:"),
                    "link must not serve non-inference intents: {}",
                    r.summary
                );
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn inference_intent_without_link_keeps_legacy_summary() {
        let mut agent = TaskAgent::new(test_agent_id());
        agent.spawn().await.unwrap();

        let reply = agent
            .handle_message(intent_message("explain the boot sequence"))
            .await
            .unwrap();
        match reply.payload {
            MessagePayload::OperationResult(r) => {
                assert!(r.success);
                assert!(!r.summary.starts_with("ANSWER:"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn link_failure_folds_into_clean_failed_result() {
        let mut agent =
            TaskAgent::new(test_agent_id()).with_runtime_link(std::sync::Arc::new(FailingLink));
        agent.spawn().await.unwrap();

        let reply = agent
            .handle_message(intent_message("explain the boot sequence"))
            .await
            .unwrap();
        match reply.payload {
            MessagePayload::OperationResult(r) => {
                assert!(!r.success);
                assert!(r.summary.contains("backend down"), "{}", r.summary);
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }
}

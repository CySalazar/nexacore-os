//! Durable, structured audit log for AI inference activity.
//!
//! This module provides a tamper-evident, append-only audit trail for every
//! inference invocation handled by the NexaCore OS runtime.  The log records only
//! **metadata** — token counts, latency, status, capability scope, and session
//! correlation — and never captures raw input text, raw output text, or any
//! personally identifiable information (PII).
//!
//! # Security contract
//!
//! - **No PII in log records.**  The schema deliberately omits all content
//!   fields.  Pre-processing strips PII before it reaches the runtime; the
//!   audit layer never sees the original text.
//! - **Monotone insertion.**  Records are appended in call order.  The ring
//!   buffer evicts the *oldest* record when full, preserving the most recent
//!   [`crate::audit::MAX_AUDIT_RECORDS`] entries.
//! - **No `unsafe` code.**  The ring buffer is implemented entirely in safe
//!   Rust.
//!
//! # Wire format
//!
//! [`crate::audit::AuditRecord`] derives `serde::Serialize` / `serde::Deserialize` and
//! round-trips through the workspace canonical wire encoding
//! ([`nexacore_types::wire::encode_canonical`] / [`nexacore_types::wire::decode_canonical`]).
//! The encoding is `postcard` 1.x with default options (LEB128 length
//! prefixes, little-endian scalars, deterministic field order).
//!
//! # Example
//!
//! ```rust
//! use nexacore_runtime::audit::{AuditLog, AuditRecord, AuditStatus, InMemoryAuditLog};
//! use nexacore_types::{CapabilityId, ModelId, SessionId};
//!
//! let mut log = InMemoryAuditLog::new();
//!
//! let rec = AuditRecord {
//!     timestamp_ns: 1_000_000_000,
//!     session_id: SessionId::from_bytes([0x01; 16]),
//!     capability_id: CapabilityId::from_bytes([0x02; 16]),
//!     model_id: ModelId::from_bytes([0x03; 32]),
//!     tier: 0,
//!     input_token_count: 128,
//!     output_token_count: 64,
//!     latency_us: 5_000,
//!     status: AuditStatus::Ok,
//!     backend_used: Some(nexacore_types::ai::BackendKind::RemoteGpu),
//! };
//!
//! log.record(rec.clone());
//!
//! let entries: Vec<&AuditRecord> = log.iter().collect();
//! assert_eq!(entries.len(), 1);
//! assert_eq!(entries[0].input_token_count, 128);
//! ```

use nexacore_types::{CapabilityId, ModelId, SessionId, ai::BackendKind};
use serde::{Deserialize, Serialize};
use tracing::debug;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of [`AuditRecord`]s retained in [`InMemoryAuditLog`].
///
/// When this limit is reached the oldest entry is silently evicted to make
/// room for the new record.  Callers that require indefinite retention must
/// flush to persistent storage before the log wraps.
pub const MAX_AUDIT_RECORDS: usize = 16_384;

// =============================================================================
// AuditStatus
// =============================================================================

/// Outcome of a single AI inference invocation.
///
/// The status is the high-level classification recorded in the audit log.
/// It does not carry an error message (which could contain PII); callers
/// can correlate via `session_id` and `timestamp_ns` to find the matching
/// structured error in the runtime's diagnostic trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditStatus {
    /// The inference call completed without error.
    Ok,
    /// The call was rejected before reaching the model (e.g., capability
    /// check failed, model not loaded, tier policy denied).
    Rejected,
    /// The call reached the model but the inference itself failed (e.g.,
    /// tensor backend error, timeout, OOM).
    Failed,
}

// =============================================================================
// AuditRecord
// =============================================================================

/// A single immutable audit record for one AI inference invocation.
///
/// Fields capture **metadata only** — no input text, no output text, no PII.
/// The full set of fields is intentional: anything not listed here must not
/// be added without a security review and an update to the privacy policy
/// section in `/docs/04-security-model.md`.
///
/// # Wire encoding
///
/// `AuditRecord` serializes deterministically via
/// [`nexacore_types::wire::encode_canonical`].  Field order in the `Serialize`
/// output matches textual declaration order (serde's default for structs).
/// Reordering fields is a **wire-format breaking change**.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::audit::{AuditRecord, AuditStatus};
/// use nexacore_types::{
///     CapabilityId, ModelId, SessionId,
///     wire::{decode_canonical, encode_canonical},
/// };
///
/// let rec = AuditRecord {
///     timestamp_ns: 42_000_000_000,
///     session_id: SessionId::from_bytes([0xAA; 16]),
///     capability_id: CapabilityId::from_bytes([0xBB; 16]),
///     model_id: ModelId::from_bytes([0xCC; 32]),
///     tier: 1,
///     input_token_count: 256,
///     output_token_count: 128,
///     latency_us: 12_500,
///     status: AuditStatus::Ok,
///     backend_used: Some(nexacore_types::ai::BackendKind::RemoteGpu),
/// };
///
/// let bytes = encode_canonical(&rec).expect("encode succeeds");
/// let decoded: AuditRecord = decode_canonical(&bytes).expect("decode succeeds");
/// assert_eq!(decoded, rec);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Wall-clock timestamp of the invocation in nanoseconds since the
    /// Unix epoch.  Populated by the caller; the audit log preserves
    /// whatever value is supplied.
    pub timestamp_ns: u64,

    /// Session identifier grouping a sequence of related inference calls
    /// (e.g., a conversation turn).  Correlates records across the log
    /// without exposing user identity.
    pub session_id: SessionId,

    /// Capability token identifier that authorized this call.  The full
    /// capability token is held by `nexacore-capability`; the audit log stores
    /// only the 16-byte ID so it can answer "which capability was used?"
    /// without carrying the full token.
    pub capability_id: CapabilityId,

    /// Content-addressed model identifier.  Matches the [`ModelId`] stored
    /// in [`crate::model::ModelRegistry`].
    pub model_id: ModelId,

    /// Execution tier on which the inference ran (0 = local, 1 = personal
    /// cluster, 2 = federated mesh, 3 = commercial cloud).  Invariant:
    /// `tier ∈ 0..=3`.  Values outside that range are accepted but
    /// semantically undefined.
    pub tier: u8,

    /// Number of tokens in the (pre-processed, PII-stripped) input.
    pub input_token_count: u32,

    /// Number of tokens produced by the model.
    pub output_token_count: u32,

    /// Wall-clock latency of the full inference dispatch in microseconds.
    pub latency_us: u64,

    /// High-level outcome of the invocation.
    pub status: AuditStatus,

    /// Which inference backend actually served (or terminally rejected)
    /// the request — TASK-10 (DE-G5). `None` when no backend produced
    /// the outcome: the request was rejected before dispatch, or every
    /// permitted backend was unreachable.
    ///
    /// Metadata-only like every other field (a two-variant enum; no
    /// content, no PII) — consistent with GDPR data-minimisation.
    ///
    /// **Wire note:** appended in TASK-10. postcard is not
    /// self-describing, so records encoded before this field existed do
    /// not decode as the current struct; no persisted audit logs existed
    /// at the time of the change (pre-release, in-memory ring only).
    pub backend_used: Option<BackendKind>,
}

// =============================================================================
// AuditLog trait
// =============================================================================

/// Behaviour required of any audit log implementation.
///
/// Implementors must preserve insertion order for the records they retain.
/// The trait deliberately does not expose a mutable iterator or a delete
/// operation: audit logs are append-only by design.
pub trait AuditLog {
    /// Append `rec` to the log.
    ///
    /// If the log's capacity is exhausted the implementation may silently
    /// discard the oldest record; callers must not assume that every
    /// appended record is retained indefinitely.
    fn record(&mut self, rec: AuditRecord);

    /// Return all records whose `session_id` matches `id`.
    ///
    /// The returned slice references records in insertion order.
    fn query_by_session(&self, id: SessionId) -> Vec<&AuditRecord>;

    /// Return all records whose `model_id` matches `id`.
    ///
    /// The returned slice references records in insertion order.
    fn query_by_model(&self, id: ModelId) -> Vec<&AuditRecord>;

    /// Iterate over all retained records in insertion order.
    fn iter(&self) -> impl Iterator<Item = &AuditRecord>;
}

// =============================================================================
// AuditSink
// =============================================================================

/// A shareable, interior-mutability handle for *writing* audit records.
///
/// [`AuditLog`] requires `&mut self` (and its `iter` method makes it
/// non-dyn-compatible), which is right for the owner of the log but
/// unusable as a shared sink on the request path. `AuditSink` is the
/// narrow, object-safe writer the [`crate::provider::BackendRouter`]
/// holds (TASK-10): one method, `&self`, `Send + Sync`.
///
/// The canonical implementation is `parking_lot::Mutex<L>` over any
/// [`AuditLog`], provided below — callers share it as
/// `Arc<parking_lot::Mutex<InMemoryAuditLog>>` and keep full read access
/// through the same handle.
pub trait AuditSink: Send + Sync {
    /// Append one record to the underlying log.
    fn record_event(&self, rec: AuditRecord);
}

/// The canonical sink: a `parking_lot` mutex over any [`AuditLog`].
///
/// `parking_lot::Mutex` is the workspace-standard sync lock (no
/// `PoisonError`); the critical section is a ring-buffer write, so
/// holding it inline on the request path is cheap.
impl<L: AuditLog + Send> AuditSink for parking_lot::Mutex<L> {
    fn record_event(&self, rec: AuditRecord) {
        self.lock().record(rec);
    }
}

/// `Arc<S>` forwards to `S`, so the same sink can be shared between the
/// router (writer) and the owner that queries the log (reader).
impl<S: AuditSink + ?Sized> AuditSink for std::sync::Arc<S> {
    fn record_event(&self, rec: AuditRecord) {
        S::record_event(self, rec);
    }
}

// =============================================================================
// InMemoryAuditLog
// =============================================================================

/// In-memory ring-buffer audit log with a fixed capacity of
/// [`MAX_AUDIT_RECORDS`] entries.
///
/// When the buffer is full the **oldest** record is evicted to make room for
/// the new one.  The eviction policy is FIFO: the ring tail advances one
/// position and the record at that position is overwritten.
///
/// Records are iterated in **insertion order** (oldest to newest among the
/// currently retained records).
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::audit::{AuditLog, AuditRecord, AuditStatus, InMemoryAuditLog};
/// use nexacore_types::{CapabilityId, ModelId, SessionId};
///
/// let mut log = InMemoryAuditLog::new();
///
/// let rec = AuditRecord {
///     timestamp_ns: 1,
///     session_id: SessionId::from_bytes([0x01; 16]),
///     capability_id: CapabilityId::from_bytes([0x02; 16]),
///     model_id: ModelId::from_bytes([0x03; 32]),
///     tier: 0,
///     input_token_count: 10,
///     output_token_count: 5,
///     latency_us: 100,
///     status: AuditStatus::Ok,
///     backend_used: None,
/// };
///
/// log.record(rec.clone());
/// log.record(rec.clone());
///
/// let all: Vec<&AuditRecord> = log.iter().collect();
/// assert_eq!(all.len(), 2);
/// assert_eq!(all[0].timestamp_ns, 1);
/// ```
#[derive(Debug)]
pub struct InMemoryAuditLog {
    /// Storage ring.  Entries are stored at indices `[head..head+len) % capacity`.
    /// `head` points to the oldest retained record when `len == MAX_AUDIT_RECORDS`.
    buf: Vec<Option<AuditRecord>>,
    /// Index of the next write position.
    head: usize,
    /// Number of valid entries currently in the ring.
    len: usize,
}

impl Default for InMemoryAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryAuditLog {
    /// Create an empty log with capacity [`MAX_AUDIT_RECORDS`].
    ///
    /// ```rust
    /// use nexacore_runtime::audit::InMemoryAuditLog;
    /// let log = InMemoryAuditLog::new();
    /// assert_eq!(log.count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        // Pre-allocate the full ring buffer as `None` entries.
        // Capacity is fixed; no reallocation will occur after construction.
        Self {
            buf: vec![None; MAX_AUDIT_RECORDS],
            head: 0,
            len: 0,
        }
    }

    /// Return the number of records currently retained in the log.
    ///
    /// The count never exceeds [`MAX_AUDIT_RECORDS`].
    ///
    /// ```rust
    /// use nexacore_runtime::audit::{AuditLog, AuditRecord, AuditStatus, InMemoryAuditLog};
    /// use nexacore_types::{CapabilityId, ModelId, SessionId};
    ///
    /// let mut log = InMemoryAuditLog::new();
    /// assert_eq!(log.count(), 0);
    ///
    /// let rec = AuditRecord {
    ///     timestamp_ns: 0,
    ///     session_id: SessionId::from_bytes([0; 16]),
    ///     capability_id: CapabilityId::from_bytes([0; 16]),
    ///     model_id: ModelId::from_bytes([0; 32]),
    ///     tier: 0,
    ///     input_token_count: 0,
    ///     output_token_count: 0,
    ///     latency_us: 0,
    ///     status: AuditStatus::Ok,
    ///     backend_used: None,
    /// };
    /// log.record(rec);
    /// assert_eq!(log.count(), 1);
    /// ```
    #[must_use]
    pub fn count(&self) -> usize {
        self.len
    }

    /// Translate a logical index (0 = oldest) into a physical buffer index.
    ///
    /// When the ring is not yet full, `head` is always 0 (the ring grows
    /// from the front) so the physical index equals the logical index.
    /// When the ring is full, `head` is the write cursor which also marks
    /// the start of the oldest entry.
    fn physical_index(&self, logical: usize) -> usize {
        if self.len < MAX_AUDIT_RECORDS {
            // Ring not yet wrapped: records live at [0, len).
            logical
        } else {
            // Ring full: oldest record is at `head`; wrap around capacity.
            (self.head + logical) % MAX_AUDIT_RECORDS
        }
    }
}

impl AuditLog for InMemoryAuditLog {
    /// Append `rec` to the log, evicting the oldest entry if the ring is full.
    fn record(&mut self, rec: AuditRecord) {
        debug!(
            timestamp_ns = rec.timestamp_ns,
            session_id   = ?rec.session_id,
            model_id     = ?rec.model_id,
            status        = ?rec.status,
            "audit: recording inference event"
        );

        if self.len < MAX_AUDIT_RECORDS {
            // Ring not yet full: write at position `len` and advance `len`.
            // `head` stays at 0 during the filling phase.
            // Invariant: `self.len < MAX_AUDIT_RECORDS == self.buf.len()`.
            // The `if let` branch is always taken; the else arm is dead code
            // included for completeness (unreachable in practice).
            if let Some(slot) = self.buf.get_mut(self.len) {
                *slot = Some(rec);
            }
            self.len += 1;
        } else {
            // Ring full: overwrite the oldest slot (at `head`) and advance
            // `head` to the next slot.  The length stays at MAX_AUDIT_RECORDS.
            // Invariant: `self.head < MAX_AUDIT_RECORDS == self.buf.len()`
            // because `self.head` is always set via `% MAX_AUDIT_RECORDS`.
            if let Some(slot) = self.buf.get_mut(self.head) {
                *slot = Some(rec);
            }
            self.head = (self.head + 1) % MAX_AUDIT_RECORDS;
        }
    }

    /// Return all records matching `id` in insertion order.
    fn query_by_session(&self, id: SessionId) -> Vec<&AuditRecord> {
        self.iter().filter(|r| r.session_id == id).collect()
    }

    /// Return all records matching `id` in insertion order.
    fn query_by_model(&self, id: ModelId) -> Vec<&AuditRecord> {
        self.iter().filter(|r| r.model_id == id).collect()
    }

    /// Iterate over retained records from oldest to newest.
    fn iter(&self) -> impl Iterator<Item = &AuditRecord> {
        // `physical_index(i)` always returns a value in `0..MAX_AUDIT_RECORDS`
        // which equals `self.buf.len()`.  Use `.get()` rather than direct
        // indexing to satisfy `clippy::indexing_slicing`.  The inner `?` in
        // `filter_map` silently skips any `None` slot (which only arises if
        // the physical index is somehow out of bounds — an unreachable case
        // given the invariants on `head` and `len`).
        (0..self.len).filter_map(|i| {
            self.buf
                .get(self.physical_index(i))
                .and_then(Option::as_ref)
        })
    }
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use nexacore_types::wire::{decode_canonical, encode_canonical};
    use proptest::prelude::*;

    use super::*;

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    /// Build a minimal [`AuditRecord`] with a distinctive `timestamp_ns`.
    fn make_record(timestamp_ns: u64) -> AuditRecord {
        AuditRecord {
            timestamp_ns,
            session_id: SessionId::from_bytes([0x01; 16]),
            capability_id: CapabilityId::from_bytes([0x02; 16]),
            model_id: ModelId::from_bytes([0x03; 32]),
            tier: 0,
            input_token_count: 10,
            output_token_count: 5,
            latency_us: 100,
            status: AuditStatus::Ok,
            backend_used: Some(BackendKind::RemoteGpu),
        }
    }

    /// Build a record with a specific `session_id`.
    fn make_record_with_session(ts: u64, session: [u8; 16]) -> AuditRecord {
        AuditRecord {
            timestamp_ns: ts,
            session_id: SessionId::from_bytes(session),
            capability_id: CapabilityId::from_bytes([0x0A; 16]),
            model_id: ModelId::from_bytes([0x0B; 32]),
            tier: 1,
            input_token_count: 20,
            output_token_count: 10,
            latency_us: 200,
            status: AuditStatus::Ok,
            backend_used: Some(BackendKind::LocalCpu),
        }
    }

    /// Build a record with a specific `model_id`.
    fn make_record_with_model(ts: u64, model: [u8; 32]) -> AuditRecord {
        AuditRecord {
            timestamp_ns: ts,
            session_id: SessionId::from_bytes([0x0C; 16]),
            capability_id: CapabilityId::from_bytes([0x0D; 16]),
            model_id: ModelId::from_bytes(model),
            tier: 2,
            input_token_count: 30,
            output_token_count: 15,
            latency_us: 300,
            status: AuditStatus::Failed,
            backend_used: None,
        }
    }

    // -------------------------------------------------------------------------
    // Test 1: Monotone timestamps preserved in insertion order
    // -------------------------------------------------------------------------

    #[test]
    fn timestamps_preserved_in_insertion_order() {
        let mut log = InMemoryAuditLog::new();

        let timestamps = [100u64, 200, 300, 400, 500];
        for &ts in &timestamps {
            log.record(make_record(ts));
        }

        let actual: Vec<u64> = log.iter().map(|r| r.timestamp_ns).collect();
        assert_eq!(actual, timestamps, "records must appear in insertion order");
    }

    // -------------------------------------------------------------------------
    // Test 2: Ring-buffer overflow drops oldest record
    // -------------------------------------------------------------------------

    #[test]
    fn ring_buffer_overflow_drops_oldest() {
        let mut log = InMemoryAuditLog::new();

        // Fill the ring completely.
        for i in 0..MAX_AUDIT_RECORDS {
            log.record(make_record(i as u64));
        }
        assert_eq!(log.count(), MAX_AUDIT_RECORDS);

        // Insert one more — this must evict timestamp 0 (the oldest).
        log.record(make_record(MAX_AUDIT_RECORDS as u64));

        // Count must remain at MAX.
        assert_eq!(log.count(), MAX_AUDIT_RECORDS);

        // Oldest entry is now timestamp 1, not 0.
        let first = log.iter().next().expect("log must not be empty");
        assert_eq!(
            first.timestamp_ns, 1,
            "oldest record should have timestamp 1 after eviction"
        );

        // Newest entry is MAX_AUDIT_RECORDS.
        let last = log.iter().last().expect("log must not be empty");
        assert_eq!(
            last.timestamp_ns, MAX_AUDIT_RECORDS as u64,
            "newest record must be the last inserted"
        );
    }

    // -------------------------------------------------------------------------
    // Test 3: postcard round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn postcard_round_trip() {
        let original = AuditRecord {
            timestamp_ns: 9_999_999_999,
            session_id: SessionId::from_bytes([0xAA; 16]),
            capability_id: CapabilityId::from_bytes([0xBB; 16]),
            model_id: ModelId::from_bytes([0xCC; 32]),
            tier: 3,
            input_token_count: 512,
            output_token_count: 256,
            latency_us: 88_000,
            status: AuditStatus::Rejected,
            backend_used: Some(BackendKind::RemoteGpu),
        };

        let bytes = encode_canonical(&original).expect("encode_canonical must succeed");
        let decoded: AuditRecord = decode_canonical(&bytes).expect("decode_canonical must succeed");

        assert_eq!(
            decoded, original,
            "round-trip must produce identical record"
        );
    }

    // -------------------------------------------------------------------------
    // Test 4: query_by_session
    // -------------------------------------------------------------------------

    #[test]
    fn query_by_session_returns_matching_records() {
        let mut log = InMemoryAuditLog::new();

        let session_a = [0xA0u8; 16];
        let session_b = [0xB0u8; 16];

        log.record(make_record_with_session(1, session_a));
        log.record(make_record_with_session(2, session_b));
        log.record(make_record_with_session(3, session_a));
        log.record(make_record_with_session(4, session_b));
        log.record(make_record_with_session(5, session_a));

        let results_a = log.query_by_session(SessionId::from_bytes(session_a));
        assert_eq!(results_a.len(), 3, "session_a should match 3 records");
        assert!(
            results_a
                .iter()
                .all(|r| r.session_id == SessionId::from_bytes(session_a)),
            "all returned records must have the queried session_id"
        );

        let results_b = log.query_by_session(SessionId::from_bytes(session_b));
        assert_eq!(results_b.len(), 2, "session_b should match 2 records");

        // No records for an unknown session.
        let unknown = SessionId::from_bytes([0xFF; 16]);
        assert!(
            log.query_by_session(unknown).is_empty(),
            "unknown session_id must return empty vec"
        );
    }

    // -------------------------------------------------------------------------
    // Test 5: query_by_model
    // -------------------------------------------------------------------------

    #[test]
    fn query_by_model_returns_matching_records() {
        let mut log = InMemoryAuditLog::new();

        let model_x = [0x10u8; 32];
        let model_y = [0x20u8; 32];

        log.record(make_record_with_model(10, model_x));
        log.record(make_record_with_model(20, model_y));
        log.record(make_record_with_model(30, model_x));

        let results_x = log.query_by_model(ModelId::from_bytes(model_x));
        assert_eq!(results_x.len(), 2, "model_x should match 2 records");
        assert!(
            results_x
                .iter()
                .all(|r| r.model_id == ModelId::from_bytes(model_x)),
            "all returned records must have the queried model_id"
        );

        let results_y = log.query_by_model(ModelId::from_bytes(model_y));
        assert_eq!(results_y.len(), 1, "model_y should match 1 record");

        let unknown_model = ModelId::from_bytes([0xFF; 32]);
        assert!(
            log.query_by_model(unknown_model).is_empty(),
            "unknown model_id must return empty vec"
        );
    }

    // -------------------------------------------------------------------------
    // Test 6: AuditStatus variants all round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn status_variants_round_trip() {
        let statuses = [AuditStatus::Ok, AuditStatus::Rejected, AuditStatus::Failed];

        for status in statuses {
            let rec = AuditRecord {
                timestamp_ns: 0,
                session_id: SessionId::from_bytes([0; 16]),
                capability_id: CapabilityId::from_bytes([0; 16]),
                model_id: ModelId::from_bytes([0; 32]),
                tier: 0,
                input_token_count: 0,
                output_token_count: 0,
                latency_us: 0,
                status,
                backend_used: None,
            };

            let bytes = encode_canonical(&rec).expect("encode must succeed");
            let decoded: AuditRecord = decode_canonical(&bytes).expect("decode must succeed");

            assert_eq!(
                decoded.status, status,
                "status variant {status:?} must survive round-trip"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Test 7: Empty log iter returns nothing
    // -------------------------------------------------------------------------

    #[test]
    fn empty_log_iter_is_empty() {
        let log = InMemoryAuditLog::new();
        assert_eq!(log.iter().count(), 0, "empty log must yield no records");
    }

    // -------------------------------------------------------------------------
    // Test 8: Multiple overflow cycles preserve FIFO invariant
    // -------------------------------------------------------------------------

    #[test]
    fn multiple_overflow_cycles_preserve_fifo() {
        let mut log = InMemoryAuditLog::new();

        // Insert 2× capacity to exercise two full wrap-arounds.
        let total = MAX_AUDIT_RECORDS * 2;
        for i in 0..total {
            log.record(make_record(i as u64));
        }

        assert_eq!(log.count(), MAX_AUDIT_RECORDS);

        // After 2 full passes the retained window is [total - MAX, total).
        let expected_start = (total - MAX_AUDIT_RECORDS) as u64;
        let first = log.iter().next().expect("log must not be empty");
        assert_eq!(
            first.timestamp_ns, expected_start,
            "first retained record must be the (total - MAX)-th inserted"
        );

        // Verify strict ordering across all retained records.
        let all: Vec<u64> = log.iter().map(|r| r.timestamp_ns).collect();
        assert_eq!(all.len(), MAX_AUDIT_RECORDS);
        for window in all.windows(2) {
            // Pattern-match on the slice to avoid clippy::indexing_slicing.
            // `windows(2)` always yields slices of exactly length 2.
            if let [a, b] = window {
                assert!(
                    a < b,
                    "records must remain in strictly ascending insertion order"
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // proptest: arbitrary AuditRecord survives postcard round-trip
    // -------------------------------------------------------------------------

    proptest! {
        #[test]
        fn proptest_audit_record_postcard_round_trip(
            timestamp_ns in any::<u64>(),
            session_bytes in any::<[u8; 16]>(),
            cap_bytes in any::<[u8; 16]>(),
            model_bytes in any::<[u8; 32]>(),
            tier in 0u8..=3,
            input_tokens in any::<u32>(),
            output_tokens in any::<u32>(),
            latency_us in any::<u64>(),
            status_idx in 0usize..3,
            backend_idx in 0usize..3,
        ) {
            let status = match status_idx {
                0 => AuditStatus::Ok,
                1 => AuditStatus::Rejected,
                _ => AuditStatus::Failed,
            };
            let backend_used = match backend_idx {
                0 => None,
                1 => Some(BackendKind::RemoteGpu),
                _ => Some(BackendKind::LocalCpu),
            };

            let rec = AuditRecord {
                timestamp_ns,
                session_id: SessionId::from_bytes(session_bytes),
                capability_id: CapabilityId::from_bytes(cap_bytes),
                model_id: ModelId::from_bytes(model_bytes),
                tier,
                input_token_count: input_tokens,
                output_token_count: output_tokens,
                latency_us,
                status,
                backend_used,
            };

            let bytes = encode_canonical(&rec).expect("encode must always succeed for AuditRecord");
            let decoded: AuditRecord = decode_canonical(&bytes)
                .expect("decode must succeed for bytes produced by encode_canonical");

            prop_assert_eq!(decoded, rec);
        }
    }

    // -------------------------------------------------------------------------
    // Test 9: AuditSink over a shared mutex-guarded log (TASK-10)
    // -------------------------------------------------------------------------

    #[test]
    fn audit_sink_over_shared_mutex_records_into_the_log() {
        use std::sync::Arc;

        let shared = Arc::new(parking_lot::Mutex::new(InMemoryAuditLog::new()));

        // The writer half: the same Arc, used through the AuditSink trait
        // (as the BackendRouter holds it).
        let sink: Arc<dyn AuditSink> = shared.clone();
        sink.record_event(make_record(7));
        sink.record_event(make_record(8));

        // The reader half sees both records through the original handle.
        // (Collect under a statement-scoped lock so the guard drops at
        // the semicolon — keeps clippy::significant_drop_tightening
        // satisfied.)
        let records: Vec<AuditRecord> = shared.lock().iter().cloned().collect();
        let timestamps: Vec<u64> = records.iter().map(|r| r.timestamp_ns).collect();
        assert_eq!(timestamps, vec![7, 8]);
        assert_eq!(
            records.first().expect("non-empty").backend_used,
            Some(BackendKind::RemoteGpu)
        );
    }
}

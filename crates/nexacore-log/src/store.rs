//! Ingestion bus, persistent ring store, and indices (WS12-03.2/.3/.4).
//!
//! [`LogStore`] is the journald-class core: `ingest` is the ingestion bus — it
//! stamps each incoming [`LogRecord`] with a monotonic sequence number, appends
//! it to durable storage through the [`LogSink`] seam, pushes it into a bounded
//! in-memory ring (rotating the oldest entry out when full), and maintains
//! per-service and per-severity indices. On restart, [`LogStore::recover`]
//! rebuilds the ring and indices from whatever the sink persisted — this is
//! what lets logs survive a reboot.

use alloc::{
    collections::{BTreeMap, VecDeque},
    string::String,
    vec::Vec,
};

use crate::record::{LogRecord, Severity};

/// Maximum structured fields the bus will keep on a single record; extra
/// fields are dropped so a misbehaving emitter cannot bloat the ring.
pub const MAX_FIELDS: usize = 32;

/// Durable storage seam for the ring. A real deployment writes to a rotated
/// on-disk journal (via the VFS / block device); host tests use [`MemSink`].
///
/// The store treats the sink as an append-only log with its own rotation
/// budget: `append` persists one encoded record and may internally drop the
/// oldest, and `load` returns the surviving encoded records in order.
pub trait LogSink {
    /// Persist one encoded record. Implementations may rotate (drop oldest)
    /// to stay within a durable budget.
    fn append(&mut self, encoded: &[u8]);

    /// Return the surviving encoded records, oldest first, for recovery.
    fn load(&self) -> Vec<Vec<u8>>;
}

/// An in-memory [`LogSink`] with record-count rotation, standing in for durable
/// storage in tests. Reconstructing a fresh `MemSink` from another's [`load`]
/// output models the reboot boundary.
///
/// [`load`]: LogSink::load
pub struct MemSink {
    records: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl MemSink {
    /// A sink that retains at most `capacity` encoded records.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            records: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Seed a sink with previously-persisted records (e.g. from disk at boot).
    #[must_use]
    pub fn from_records(capacity: usize, records: Vec<Vec<u8>>) -> Self {
        let mut s = Self::new(capacity);
        for r in records {
            s.append(&r);
        }
        s
    }
}

impl LogSink for MemSink {
    fn append(&mut self, encoded: &[u8]) {
        if self.records.len() >= self.capacity {
            self.records.pop_front();
        }
        self.records.push_back(encoded.to_vec());
    }

    fn load(&self) -> Vec<Vec<u8>> {
        self.records.iter().cloned().collect()
    }
}

/// The structured logging core: ingestion bus + bounded ring + indices, over a
/// pluggable [`LogSink`].
pub struct LogStore<S: LogSink> {
    sink: S,
    ring: VecDeque<LogRecord>,
    capacity: usize,
    next_seq: u64,
    by_service: BTreeMap<String, Vec<u64>>,
    by_severity: BTreeMap<u8, Vec<u64>>,
}

impl<S: LogSink> LogStore<S> {
    /// Create a store with an in-memory ring holding at most `capacity`
    /// records, backed by `sink`.
    #[must_use]
    pub fn new(sink: S, capacity: usize) -> Self {
        Self {
            sink,
            ring: VecDeque::new(),
            capacity: capacity.max(1),
            next_seq: 1,
            by_service: BTreeMap::new(),
            by_severity: BTreeMap::new(),
        }
    }

    /// Rebuild a store from a sink's persisted records (reboot recovery). The
    /// ring and indices are repopulated in sequence order and `next_seq`
    /// resumes after the highest recovered sequence.
    #[must_use]
    pub fn recover(sink: S, capacity: usize) -> Self {
        let mut store = Self::new(sink, capacity);
        let persisted = store.sink.load();
        let mut max_seq = 0u64;
        for enc in persisted {
            if let Some((rec, _)) = LogRecord::decode(&enc) {
                max_seq = max_seq.max(rec.seq);
                store.insert_recovered(rec);
            }
        }
        store.next_seq = max_seq.saturating_add(1);
        store
    }

    /// The ingestion bus: stamp `record` with the next sequence number, persist
    /// it, and index it. Returns the assigned sequence number.
    pub fn ingest(&mut self, mut record: LogRecord) -> u64 {
        record.seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        record.fields.truncate(MAX_FIELDS);

        self.sink.append(&record.encode());
        self.push_ring(record);
        self.next_seq.saturating_sub(1)
    }

    /// Number of records currently held in the in-memory ring.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ring.len()
    }

    /// Whether the ring is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    /// All records currently in the ring, oldest first.
    pub fn records(&self) -> impl Iterator<Item = &LogRecord> {
        self.ring.iter()
    }

    /// Sequence numbers logged by `service`, oldest first (index lookup).
    #[must_use]
    pub fn seqs_for_service(&self, service: &str) -> &[u64] {
        self.by_service.get(service).map_or(&[], Vec::as_slice)
    }

    /// Sequence numbers at exactly `severity`, oldest first (index lookup).
    #[must_use]
    pub fn seqs_for_severity(&self, severity: Severity) -> &[u64] {
        self.by_severity
            .get(&(severity as u8))
            .map_or(&[], Vec::as_slice)
    }

    /// The distinct service names currently indexed, sorted.
    #[must_use]
    pub fn services(&self) -> Vec<&str> {
        self.by_service.keys().map(String::as_str).collect()
    }

    /// Look up a record in the ring by sequence number.
    #[must_use]
    pub fn get(&self, seq: u64) -> Option<&LogRecord> {
        self.ring.iter().find(|r| r.seq == seq)
    }

    // ---- internals ----------------------------------------------------------

    fn push_ring(&mut self, record: LogRecord) {
        if self.ring.len() >= self.capacity {
            if let Some(evicted) = self.ring.pop_front() {
                self.deindex(&evicted);
            }
        }
        self.index(&record);
        self.ring.push_back(record);
    }

    fn insert_recovered(&mut self, record: LogRecord) {
        // Same as push_ring but without re-persisting to the sink.
        if self.ring.len() >= self.capacity {
            if let Some(evicted) = self.ring.pop_front() {
                self.deindex(&evicted);
            }
        }
        self.index(&record);
        self.ring.push_back(record);
    }

    fn index(&mut self, record: &LogRecord) {
        self.by_service
            .entry(record.service.clone())
            .or_default()
            .push(record.seq);
        self.by_severity
            .entry(record.severity as u8)
            .or_default()
            .push(record.seq);
    }

    fn deindex(&mut self, record: &LogRecord) {
        if let Some(v) = self.by_service.get_mut(&record.service) {
            v.retain(|&s| s != record.seq);
            if v.is_empty() {
                self.by_service.remove(&record.service);
            }
        }
        if let Some(v) = self.by_severity.get_mut(&(record.severity as u8)) {
            v.retain(|&s| s != record.seq);
            if v.is_empty() {
                self.by_severity.remove(&(record.severity as u8));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn rec(ts: u64, sev: Severity, svc: &str, msg: &str) -> LogRecord {
        LogRecord::new(ts, sev, svc, msg)
    }

    #[test]
    fn ingest_assigns_monotonic_sequences() {
        let mut store = LogStore::new(MemSink::new(100), 100);
        assert_eq!(store.ingest(rec(1, Severity::Info, "a", "x")), 1);
        assert_eq!(store.ingest(rec(2, Severity::Info, "a", "y")), 2);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn ring_rotates_oldest_out_and_deindexes() {
        let mut store = LogStore::new(MemSink::new(100), 2);
        store.ingest(rec(1, Severity::Info, "a", "1"));
        store.ingest(rec(2, Severity::Warning, "b", "2"));
        store.ingest(rec(3, Severity::Info, "a", "3")); // evicts seq 1
        assert_eq!(store.len(), 2);
        assert!(store.get(1).is_none());
        // seq 1 was service "a"; only seq 3 remains for "a".
        assert_eq!(store.seqs_for_service("a"), &[3]);
        // seq 2 (service "b") still present.
        assert_eq!(store.seqs_for_service("b"), &[2]);
    }

    #[test]
    fn indices_track_service_and_severity() {
        let mut store = LogStore::new(MemSink::new(100), 100);
        store.ingest(rec(1, Severity::Error, "net", "e"));
        store.ingest(rec(2, Severity::Info, "net", "i"));
        store.ingest(rec(3, Severity::Error, "kernel", "e"));
        assert_eq!(store.seqs_for_service("net"), &[1, 2]);
        assert_eq!(store.seqs_for_severity(Severity::Error), &[1, 3]);
        assert_eq!(store.services(), alloc::vec!["kernel", "net"]);
    }

    #[test]
    fn recover_survives_a_reboot() {
        // First boot: ingest into a MemSink acting as durable storage.
        let mut store = LogStore::new(MemSink::new(100), 100);
        store.ingest(rec(1, Severity::Warning, "net", "link down"));
        store.ingest(rec(2, Severity::Info, "ui", "ready"));
        // Simulate a reboot: persist the durable bytes, then rebuild a fresh
        // store + sink from them.
        let persisted = store.sink.load();
        let sink2 = MemSink::from_records(100, persisted);
        let recovered = LogStore::recover(sink2, 100);
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered.get(1).unwrap().message, "link down");
        assert_eq!(recovered.seqs_for_service("ui"), &[2]);
        // next_seq resumes after the highest recovered sequence.
        let mut recovered = recovered;
        assert_eq!(recovered.ingest(rec(3, Severity::Info, "net", "up")), 3);
    }

    #[test]
    fn bus_caps_field_count() {
        let mut store = LogStore::new(MemSink::new(10), 10);
        let mut r = rec(1, Severity::Info, "svc", "m");
        for i in 0..100u32 {
            r.fields
                .push((alloc::format!("k{i}"), alloc::string::String::from("v")));
        }
        store.ingest(r);
        assert_eq!(store.get(1).unwrap().fields.len(), MAX_FIELDS);
    }
}

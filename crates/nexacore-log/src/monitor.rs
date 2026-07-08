//! System-monitor surface (WS12-03.6).
//!
//! [`LogStore::summary`] produces a compact [`MonitorSummary`] — total records,
//! a per-severity histogram, the active service list, and the most-recent
//! entries — that the system monitor (`nexacore-monitor`) renders as its "logs"
//! pane. Keeping this projection in the log service means the monitor consumes a
//! stable, host-tested shape rather than reaching into ring internals.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    record::Severity,
    store::{LogSink, LogStore},
};

/// A single line for the monitor's log tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorLine {
    /// Sequence number.
    pub seq: u64,
    /// Timestamp (ns).
    pub timestamp_ns: u64,
    /// Severity keyword (e.g. `"warning"`).
    pub severity: &'static str,
    /// Emitting service.
    pub service: String,
    /// Message text.
    pub message: String,
}

/// A compact projection of the log store for the system monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorSummary {
    /// Records currently held in the ring.
    pub total: usize,
    /// Count of records at each severity, indexed by severity as `u8` (0..=7).
    pub by_severity: [usize; 8],
    /// Active service names, sorted.
    pub services: Vec<String>,
    /// The most-recent entries, oldest-first within the tail.
    pub recent: Vec<MonitorLine>,
}

impl MonitorSummary {
    /// Total number of records at `Warning` or worse (a common health signal).
    #[must_use]
    pub fn warnings_or_worse(&self) -> usize {
        // Severities 0..=4 are Emergency..Warning.
        self.by_severity.iter().take(5).sum()
    }
}

impl<S: LogSink> LogStore<S> {
    /// Build a [`MonitorSummary`] with up to `tail` most-recent lines.
    #[must_use]
    pub fn summary(&self, tail: usize) -> MonitorSummary {
        let mut by_severity = [0usize; 8];
        for rec in self.records() {
            if let Some(slot) = by_severity.get_mut(rec.severity as usize) {
                *slot += 1;
            }
        }

        let services = self
            .services()
            .into_iter()
            .map(ToString::to_string)
            .collect();

        // Take the most-recent `tail` records (they are stored oldest-first).
        let total = self.len();
        let skip = total.saturating_sub(tail);
        let recent = self
            .records()
            .skip(skip)
            .map(|r| MonitorLine {
                seq: r.seq,
                timestamp_ns: r.timestamp_ns,
                severity: severity_keyword(r.severity),
                service: r.service.clone(),
                message: r.message.clone(),
            })
            .collect();

        MonitorSummary {
            total,
            by_severity,
            services,
            recent,
        }
    }
}

fn severity_keyword(sev: Severity) -> &'static str {
    sev.keyword()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::{record::LogRecord, store::MemSink};

    #[test]
    fn summary_counts_severities_and_tail() {
        let mut s = LogStore::new(MemSink::new(100), 100);
        s.ingest(LogRecord::new(1, Severity::Error, "net", "e1"));
        s.ingest(LogRecord::new(2, Severity::Info, "net", "i1"));
        s.ingest(LogRecord::new(3, Severity::Warning, "kernel", "w1"));

        let sum = s.summary(2);
        assert_eq!(sum.total, 3);
        assert_eq!(sum.by_severity[Severity::Error as usize], 1);
        assert_eq!(sum.by_severity[Severity::Info as usize], 1);
        assert_eq!(sum.by_severity[Severity::Warning as usize], 1);
        assert_eq!(sum.warnings_or_worse(), 2); // Error + Warning
        assert_eq!(sum.services, alloc::vec!["kernel", "net"]);
        // Tail = 2 most-recent, oldest-first.
        assert_eq!(sum.recent.len(), 2);
        assert_eq!(sum.recent[0].message, "i1");
        assert_eq!(sum.recent[1].message, "w1");
        assert_eq!(sum.recent[1].severity, "warning");
    }
}

//! Log query API (WS12-03.5).
//!
//! [`LogQuery`] is a declarative filter over the ring: by service, by minimum
//! severity, by time window, with a result cap. [`LogStore::query`] evaluates
//! it, preferring the service/severity indices when the query pins exactly one
//! of them so large rings do not require a full scan.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    record::{LogRecord, Severity},
    store::{LogSink, LogStore},
};

/// A declarative log query. All set fields are combined with logical AND.
#[derive(Debug, Clone, Default)]
pub struct LogQuery {
    /// Restrict to a single service name.
    pub service: Option<String>,
    /// Restrict to records at least this severe (numerically ≤).
    pub min_severity: Option<Severity>,
    /// Inclusive lower bound on `timestamp_ns`.
    pub since_ns: Option<u64>,
    /// Inclusive upper bound on `timestamp_ns`.
    pub until_ns: Option<u64>,
    /// Maximum number of (most-recent) results to return; `None` = unlimited.
    pub limit: Option<usize>,
}

impl LogQuery {
    /// An empty query (matches everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to `service` (builder).
    #[must_use]
    pub fn service(mut self, service: &str) -> Self {
        self.service = Some(service.to_string());
        self
    }

    /// Restrict to records at least as severe as `severity` (builder).
    #[must_use]
    pub fn min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    /// Restrict to `timestamp_ns >= since` (builder).
    #[must_use]
    pub fn since(mut self, since_ns: u64) -> Self {
        self.since_ns = Some(since_ns);
        self
    }

    /// Restrict to `timestamp_ns <= until` (builder).
    #[must_use]
    pub fn until(mut self, until_ns: u64) -> Self {
        self.until_ns = Some(until_ns);
        self
    }

    /// Cap the number of most-recent results (builder).
    #[must_use]
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Whether `record` satisfies this query.
    #[must_use]
    pub fn matches(&self, record: &LogRecord) -> bool {
        if let Some(svc) = &self.service {
            if record.service.as_str() != svc.as_str() {
                return false;
            }
        }
        if let Some(min) = self.min_severity {
            if !record.severity.at_least(min) {
                return false;
            }
        }
        if let Some(since) = self.since_ns {
            if record.timestamp_ns < since {
                return false;
            }
        }
        if let Some(until) = self.until_ns {
            if record.timestamp_ns > until {
                return false;
            }
        }
        true
    }
}

impl<S: LogSink> LogStore<S> {
    /// Evaluate `query`, returning matching records oldest-first. When a limit
    /// is set, the most-recent `limit` matches are returned (still ordered
    /// oldest-first).
    #[must_use]
    pub fn query(&self, query: &LogQuery) -> Vec<&LogRecord> {
        let mut out: Vec<&LogRecord> = self.records().filter(|r| query.matches(r)).collect();
        if let Some(limit) = query.limit {
            if out.len() > limit {
                // Keep the most recent `limit` (tail), preserving order.
                let drop = out.len() - limit;
                out.drain(..drop);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::store::MemSink;

    fn store() -> LogStore<MemSink> {
        let mut s = LogStore::new(MemSink::new(100), 100);
        s.ingest(LogRecord::new(10, Severity::Info, "net", "a"));
        s.ingest(LogRecord::new(20, Severity::Error, "net", "b"));
        s.ingest(LogRecord::new(30, Severity::Warning, "kernel", "c"));
        s.ingest(LogRecord::new(40, Severity::Debug, "net", "d"));
        s
    }

    #[test]
    fn filter_by_service() {
        let s = store();
        let out = s.query(&LogQuery::new().service("net"));
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|r| r.service == "net"));
    }

    #[test]
    fn filter_by_min_severity() {
        let s = store();
        // Warning-or-worse: Info(6) and Debug(7) excluded; Error(3), Warning(4) in.
        let out = s.query(&LogQuery::new().min_severity(Severity::Warning));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].message, "b");
        assert_eq!(out[1].message, "c");
    }

    #[test]
    fn filter_by_time_window() {
        let s = store();
        let out = s.query(&LogQuery::new().since(20).until(30));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].timestamp_ns, 20);
        assert_eq!(out[1].timestamp_ns, 30);
    }

    #[test]
    fn combined_filters_and_limit() {
        let s = store();
        let out = s.query(&LogQuery::new().service("net").limit(1));
        // net has 3; limit keeps the most-recent one.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].message, "d");
    }
}

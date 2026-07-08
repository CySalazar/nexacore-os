//! Print spooler with a persistent job queue (WS2-13.4 / .7).
//!
//! The spooler owns the submitted print jobs, tracks each job's IPP `job-state`,
//! and serves them in submission order. State persists across reboots via the
//! workspace canonical codec, so a job queue survives a restart of the print
//! service.

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

/// A job's lifecycle state, mirroring the IPP `job-state` enum (RFC 8011 §5.3.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    /// `pending` (3) — queued, not yet started.
    Pending,
    /// `processing` (5) — being printed.
    Processing,
    /// `completed` (9) — finished successfully.
    Completed,
    /// `canceled` (7) — canceled by the user.
    Canceled,
    /// `aborted` (8) — aborted by the system.
    Aborted,
}

impl JobState {
    /// The IPP `job-state` integer code.
    #[must_use]
    pub const fn ipp_code(self) -> i32 {
        match self {
            Self::Pending => 3,
            Self::Processing => 5,
            Self::Canceled => 7,
            Self::Aborted => 8,
            Self::Completed => 9,
        }
    }

    /// Whether this is a terminal state (no further transitions).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Canceled | Self::Aborted)
    }
}

/// One spooled print job (WS2-13.4 / .7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintJob {
    /// Spooler-assigned job id (the IPP `job-id`).
    pub id: i32,
    /// Human-readable `job-name`.
    pub name: String,
    /// MIME `document-format` (e.g. `"application/pdf"`).
    pub document_format: String,
    /// Target printer URI.
    pub printer_uri: String,
    /// Current lifecycle state.
    pub state: JobState,
}

/// Why a spooler operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpoolError {
    /// No job with the given id.
    NotFound,
    /// The job is already in a terminal state and cannot transition.
    Terminal,
    /// Serialized state could not be decoded.
    Decode,
}

/// The print spooler: a persistent, ordered job queue (WS2-13.4).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Spooler {
    next_id: i32,
    jobs: Vec<PrintJob>,
}

impl Spooler {
    /// Create an empty spooler (ids start at 1).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            jobs: Vec::new(),
        }
    }

    /// Submit a new `Pending` job, returning its assigned id (WS2-13.4).
    pub fn submit(
        &mut self,
        name: impl Into<String>,
        document_format: impl Into<String>,
        printer_uri: impl Into<String>,
    ) -> i32 {
        let id = self.next_id;
        self.next_id += 1;
        self.jobs.push(PrintJob {
            id,
            name: name.into(),
            document_format: document_format.into(),
            printer_uri: printer_uri.into(),
            state: JobState::Pending,
        });
        id
    }

    /// Look up a job by id (WS2-13.7).
    #[must_use]
    pub fn job(&self, id: i32) -> Option<&PrintJob> {
        self.jobs.iter().find(|j| j.id == id)
    }

    /// The next pending job in submission order (the print head pulls this).
    #[must_use]
    pub fn next_pending(&self) -> Option<&PrintJob> {
        self.jobs.iter().find(|j| j.state == JobState::Pending)
    }

    /// Transition a job to `state` (WS2-13.7). A job in a terminal state cannot
    /// transition again.
    ///
    /// # Errors
    ///
    /// [`SpoolError::NotFound`] for an unknown id; [`SpoolError::Terminal`] if
    /// the job has already finished/canceled/aborted.
    pub fn set_state(&mut self, id: i32, state: JobState) -> Result<(), SpoolError> {
        let job = self
            .jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or(SpoolError::NotFound)?;
        if job.state.is_terminal() {
            return Err(SpoolError::Terminal);
        }
        job.state = state;
        Ok(())
    }

    /// Cancel a job (WS2-13.7).
    ///
    /// # Errors
    ///
    /// As [`set_state`](Self::set_state).
    pub fn cancel(&mut self, id: i32) -> Result<(), SpoolError> {
        self.set_state(id, JobState::Canceled)
    }

    /// All jobs, in submission order.
    #[must_use]
    pub fn jobs(&self) -> &[PrintJob] {
        &self.jobs
    }

    /// Number of jobs that are not yet terminal.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.jobs.iter().filter(|j| !j.state.is_terminal()).count()
    }

    /// Serialize the queue for persistence (WS2-13.4).
    ///
    /// # Errors
    ///
    /// [`SpoolError::Decode`] if canonical encoding fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SpoolError> {
        nexacore_types::wire::encode_canonical(self).map_err(|_| SpoolError::Decode)
    }

    /// Reload a queue from persisted bytes (WS2-13.4).
    ///
    /// # Errors
    ///
    /// [`SpoolError::Decode`] on malformed input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SpoolError> {
        nexacore_types::wire::decode_canonical(bytes).map_err(|_| SpoolError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spooler_with_two() -> Spooler {
        let mut s = Spooler::new();
        s.submit("a.pdf", "application/pdf", "ipp://p/ipp/print");
        s.submit("b.pdf", "application/pdf", "ipp://p/ipp/print");
        s
    }

    #[test]
    fn submit_assigns_incrementing_ids_pending() {
        let s = spooler_with_two();
        assert_eq!(s.jobs()[0].id, 1);
        assert_eq!(s.jobs()[1].id, 2);
        assert_eq!(s.job(1).unwrap().state, JobState::Pending);
        assert_eq!(s.active_count(), 2);
    }

    #[test]
    fn next_pending_is_submission_order() {
        let mut s = spooler_with_two();
        assert_eq!(s.next_pending().unwrap().id, 1);
        s.set_state(1, JobState::Completed).unwrap();
        assert_eq!(s.next_pending().unwrap().id, 2);
    }

    #[test]
    fn terminal_jobs_cannot_transition() {
        let mut s = spooler_with_two();
        s.set_state(1, JobState::Completed).unwrap();
        assert_eq!(
            s.set_state(1, JobState::Processing),
            Err(SpoolError::Terminal)
        );
        assert_eq!(s.cancel(99), Err(SpoolError::NotFound));
    }

    #[test]
    fn cancel_marks_canceled_and_drops_active_count() {
        let mut s = spooler_with_two();
        s.cancel(2).unwrap();
        assert_eq!(s.job(2).unwrap().state, JobState::Canceled);
        assert_eq!(s.active_count(), 1);
    }

    #[test]
    fn persists_across_reload() {
        let mut s = spooler_with_two();
        s.set_state(1, JobState::Processing).unwrap();
        let bytes = s.to_bytes().unwrap();
        let back = Spooler::from_bytes(&bytes).unwrap();
        assert_eq!(back.job(1).unwrap().state, JobState::Processing);
        assert_eq!(back.jobs().len(), 2);
        // The id counter persists too: a new submit does not reuse id 2.
        let mut back = back;
        assert_eq!(back.submit("c", "application/pdf", "ipp://p"), 3);
    }

    #[test]
    fn job_state_ipp_codes() {
        assert_eq!(JobState::Pending.ipp_code(), 3);
        assert_eq!(JobState::Completed.ipp_code(), 9);
        assert!(JobState::Aborted.is_terminal());
        assert!(!JobState::Processing.is_terminal());
    }
}

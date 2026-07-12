//! Job control: background job table + process-effect seam.
//!
//! [`crate::job::JobTable`] models the shell's set of background jobs. Each [`crate::job::Job`] carries
//! a session-unique id, a process-group id (`pgid`), a [`crate::job::JobState`], and its
//! originating command line. The table implements the three POSIX job-control
//! operations:
//!
//! - `jobs` — list every job ([`crate::job::JobTable::jobs`]).
//! - `fg` — foreground a job ([`crate::job::JobTable::fg`]): resume it if stopped, wait for
//!   it, and mark it [`crate::job::JobState::Done`].
//! - `bg` — resume a *stopped* job in the background ([`crate::job::JobTable::bg`]).
//!
//! All real process effects (delivering `SIGCONT`, waiting for a group) are
//! isolated behind the [`crate::job::ProcessControl`] seam, mirroring the crate's existing
//! [`crate::glob::FsQuery`] / [`crate::netquery::NetQuery`] pattern. The table
//! itself is pure state, so its transitions are host-testable with a recording
//! test-double and require no kernel.

#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// The lifecycle state of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// The job's process group is executing.
    Running,
    /// The job has been stopped (e.g. `SIGTSTP`) and can be resumed.
    Stopped,
    /// The job has finished; its exit status has been collected.
    Done,
}

/// A single background job in the [`crate::job::JobTable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Shell-assigned job id (`%1`, `%2`, …), unique within the session.
    pub id: u32,
    /// Process-group id of the job's pipeline.
    pub pgid: i32,
    /// Current lifecycle state.
    pub state: JobState,
    /// The command line that launched the job (for `jobs` output).
    pub command: String,
}

/// Errors returned by [`crate::job::JobTable`] foreground/background operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobError {
    /// No job with the requested id exists.
    NotFound(u32),
    /// A `bg` was requested for a job that is not stopped.
    NotStopped(u32),
    /// The underlying process-control seam reported a failure.
    Process(String),
}

/// Process-control effects (signals / waiting) behind an injectable seam.
pub trait ProcessControl {
    /// Resume a stopped process group (send `SIGCONT`).
    ///
    /// # Errors
    /// Returns `Err(String)` if the signal could not be delivered.
    fn resume(&self, pgid: i32) -> Result<(), String>;

    /// Wait for a foregrounded process group to terminate, returning its exit
    /// status.
    ///
    /// # Errors
    /// Returns `Err(String)` if the group could not be waited on.
    fn wait(&self, pgid: i32) -> Result<i32, String>;
}

/// A table of background jobs owned by a shell session.
#[derive(Debug, Clone, Default)]
pub struct JobTable {
    /// Live jobs, in insertion order.
    jobs: Vec<Job>,
    /// Monotonically increasing id source.
    next_id: u32,
}

impl JobTable {
    /// Create an empty job table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            jobs: Vec::new(),
            next_id: 0,
        }
    }

    /// Register a new background job in [`crate::job::JobState::Running`] and return its
    /// freshly assigned id.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::job::{JobState, JobTable};
    ///
    /// let mut t = JobTable::new();
    /// let id = t.add(1234, "sleep 30 &");
    /// assert_eq!(id, 1);
    /// assert_eq!(t.get(id).unwrap().state, JobState::Running);
    /// ```
    pub fn add(&mut self, pgid: i32, command: &str) -> u32 {
        self.next_id += 1;
        let id = self.next_id;
        self.jobs.push(Job {
            id,
            pgid,
            state: JobState::Running,
            command: command.to_string(),
        });
        id
    }

    /// List all jobs in insertion order.
    #[must_use]
    pub fn jobs(&self) -> &[Job] {
        &self.jobs
    }

    /// Look up a job by id.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&Job> {
        self.jobs.iter().find(|j| j.id == id)
    }

    /// Mutable job lookup by id.
    fn get_mut(&mut self, id: u32) -> Option<&mut Job> {
        self.jobs.iter_mut().find(|j| j.id == id)
    }

    /// Transition a job to [`crate::job::JobState::Stopped`] (models `SIGTSTP` delivery).
    ///
    /// # Errors
    /// Returns [`crate::job::JobError::NotFound`] if `id` is unknown.
    pub fn mark_stopped(&mut self, id: u32) -> Result<(), JobError> {
        let job = self.get_mut(id).ok_or(JobError::NotFound(id))?;
        job.state = JobState::Stopped;
        Ok(())
    }

    /// Foreground the job with the given id.
    ///
    /// A stopped job is first resumed through the [`crate::job::ProcessControl`] seam
    /// (`SIGCONT`); the group is then waited on, and the job transitions to
    /// [`crate::job::JobState::Done`]. The wait's exit status is returned.
    ///
    /// # Errors
    /// - [`crate::job::JobError::NotFound`] if `id` is unknown.
    /// - [`crate::job::JobError::Process`] if the seam reports a signal/wait failure.
    pub fn fg(&mut self, id: u32, proc: &dyn ProcessControl) -> Result<i32, JobError> {
        let (pgid, stopped) = {
            let job = self.get(id).ok_or(JobError::NotFound(id))?;
            (job.pgid, job.state == JobState::Stopped)
        };
        if stopped {
            proc.resume(pgid).map_err(JobError::Process)?;
        }
        let code = proc.wait(pgid).map_err(JobError::Process)?;
        if let Some(job) = self.get_mut(id) {
            job.state = JobState::Done;
        }
        Ok(code)
    }

    /// Resume a *stopped* job in the background.
    ///
    /// Sends `SIGCONT` through the [`crate::job::ProcessControl`] seam and transitions the
    /// job back to [`crate::job::JobState::Running`].
    ///
    /// # Errors
    /// - [`crate::job::JobError::NotFound`] if `id` is unknown.
    /// - [`crate::job::JobError::NotStopped`] if the job is not currently stopped.
    /// - [`crate::job::JobError::Process`] if the seam reports a signal failure.
    pub fn bg(&mut self, id: u32, proc: &dyn ProcessControl) -> Result<(), JobError> {
        let (pgid, stopped) = {
            let job = self.get(id).ok_or(JobError::NotFound(id))?;
            (job.pgid, job.state == JobState::Stopped)
        };
        if !stopped {
            return Err(JobError::NotStopped(id));
        }
        proc.resume(pgid).map_err(JobError::Process)?;
        if let Some(job) = self.get_mut(id) {
            job.state = JobState::Running;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use super::*;

    /// Host test-double: records every seam call and returns a preset exit code.
    struct RecordingProc {
        events: RefCell<Vec<(&'static str, i32)>>,
        wait_code: i32,
    }

    impl RecordingProc {
        fn new(wait_code: i32) -> Self {
            Self {
                events: RefCell::new(Vec::new()),
                wait_code,
            }
        }
    }

    impl ProcessControl for RecordingProc {
        fn resume(&self, pgid: i32) -> Result<(), String> {
            self.events.borrow_mut().push(("resume", pgid));
            Ok(())
        }
        fn wait(&self, pgid: i32) -> Result<i32, String> {
            self.events.borrow_mut().push(("wait", pgid));
            Ok(self.wait_code)
        }
    }

    #[test]
    fn add_assigns_incrementing_ids_and_running_state() {
        let mut t = JobTable::new();
        let id1 = t.add(100, "sleep 10 &");
        let id2 = t.add(200, "build &");
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(t.jobs().len(), 2);
        assert_eq!(t.get(id1).unwrap().state, JobState::Running);
        assert_eq!(t.get(id1).unwrap().pgid, 100);
        assert_eq!(t.get(id2).unwrap().command, "build &");
    }

    #[test]
    fn get_unknown_id_is_none() {
        let t = JobTable::new();
        assert!(t.get(42).is_none());
    }

    #[test]
    fn mark_stopped_transitions_state() {
        let mut t = JobTable::new();
        let id = t.add(100, "vim &");
        t.mark_stopped(id).unwrap();
        assert_eq!(t.get(id).unwrap().state, JobState::Stopped);
    }

    #[test]
    fn mark_stopped_unknown_is_not_found() {
        let mut t = JobTable::new();
        assert_eq!(t.mark_stopped(9), Err(JobError::NotFound(9)));
    }

    #[test]
    fn fg_running_job_waits_and_marks_done() {
        let mut t = JobTable::new();
        let id = t.add(300, "server &");
        let proc = RecordingProc::new(0);
        let code = t.fg(id, &proc).unwrap();
        assert_eq!(code, 0);
        assert_eq!(t.get(id).unwrap().state, JobState::Done);
        // Running job is waited on, not resumed.
        assert_eq!(proc.events.borrow().as_slice(), &[("wait", 300)]);
    }

    #[test]
    fn fg_stopped_job_resumes_then_waits() {
        let mut t = JobTable::new();
        let id = t.add(300, "vim &");
        t.mark_stopped(id).unwrap();
        let proc = RecordingProc::new(7);
        let code = t.fg(id, &proc).unwrap();
        assert_eq!(code, 7);
        assert_eq!(t.get(id).unwrap().state, JobState::Done);
        // Stopped job is first resumed (SIGCONT) then waited on.
        assert_eq!(
            proc.events.borrow().as_slice(),
            &[("resume", 300), ("wait", 300)]
        );
    }

    #[test]
    fn fg_unknown_id_is_not_found() {
        let mut t = JobTable::new();
        let proc = RecordingProc::new(0);
        assert_eq!(t.fg(5, &proc), Err(JobError::NotFound(5)));
    }

    #[test]
    fn bg_stopped_job_resumes_and_runs() {
        let mut t = JobTable::new();
        let id = t.add(400, "make &");
        t.mark_stopped(id).unwrap();
        let proc = RecordingProc::new(0);
        t.bg(id, &proc).unwrap();
        assert_eq!(t.get(id).unwrap().state, JobState::Running);
        assert_eq!(proc.events.borrow().as_slice(), &[("resume", 400)]);
    }

    #[test]
    fn bg_running_job_is_rejected() {
        let mut t = JobTable::new();
        let id = t.add(400, "make &");
        let proc = RecordingProc::new(0);
        assert_eq!(t.bg(id, &proc), Err(JobError::NotStopped(id)));
        // No seam effect on rejection.
        assert!(proc.events.borrow().is_empty());
    }

    #[test]
    fn bg_unknown_id_is_not_found() {
        let mut t = JobTable::new();
        let proc = RecordingProc::new(0);
        assert_eq!(t.bg(5, &proc), Err(JobError::NotFound(5)));
    }
}

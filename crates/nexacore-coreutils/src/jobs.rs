//! `jobs` — format a shell job list from an injected job table (WS8-10.8).
//!
//! The **authoritative** job table lives in the shell (WS8-10.16): it is the
//! shell that forks jobs, tracks their pids, and updates their state on
//! `SIGCHLD`. This module is the *formatting, host-testable half*: given a
//! snapshot [`JobTable`] value, it renders the `jobs` listing exactly as an
//! interactive shell would, so the layout can be unit-tested without a live
//! shell.
//!
//! ## Current / previous job markers
//!
//! Following the shell convention, the most recently backgrounded job is the
//! *current* job (`+`) and the one before it is the *previous* job (`-`); all
//! others are unmarked (a space). `jobs` addresses these as `%+` and `%-`.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

/// The run state of a background job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// Running in the background.
    Running,
    /// Stopped (e.g. by `SIGTSTP`), awaiting `fg`/`bg`.
    Stopped,
    /// Finished (its exit status has not yet been reported and reaped).
    Done,
}

impl JobState {
    /// The status word shown in the `jobs` listing.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Running => "Running",
            Self::Stopped => "Stopped",
            Self::Done => "Done",
        }
    }
}

/// One background job as tracked by the shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// The job id (`%1`, `%2`, …) — small, shell-assigned, not the pid.
    pub id: u32,
    /// The leader pid of the job's process group.
    pub pid: u64,
    /// The job's run state.
    pub state: JobState,
    /// The command line, as typed (without a trailing `&`).
    pub command: String,
}

impl Job {
    /// Construct a [`Job`] from its fields.
    #[must_use]
    pub fn new(id: u32, pid: u64, state: JobState, command: &str) -> Self {
        Self {
            id,
            pid,
            state,
            command: command.to_string(),
        }
    }
}

/// A snapshot of the shell's job table, in job-id order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobTable {
    /// The jobs, kept in the order they should be listed (ascending id).
    jobs: Vec<Job>,
}

impl JobTable {
    /// An empty job table.
    #[must_use]
    pub fn new() -> Self {
        Self { jobs: Vec::new() }
    }

    /// Append a job (builder style).
    #[must_use]
    pub fn with(mut self, job: Job) -> Self {
        self.jobs.push(job);
        self
    }

    /// The jobs, in listing order.
    #[must_use]
    pub fn jobs(&self) -> &[Job] {
        &self.jobs
    }

    /// Whether the table has no jobs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    /// The marker for the job at position `index`: `+` for the current (last)
    /// job, `-` for the previous (second-to-last), a space otherwise.
    fn marker(&self, index: usize) -> char {
        let len = self.jobs.len();
        if index + 1 == len {
            '+'
        } else if index + 2 == len {
            '-'
        } else {
            ' '
        }
    }

    /// Render the job table as `jobs`-style lines: `[id]<marker>  <State>  cmd`.
    ///
    /// A `Running` job's command is suffixed with ` &`, matching an interactive
    /// shell. An empty table yields no lines (a bare `jobs` prints nothing).
    #[must_use]
    pub fn list_lines(&self) -> Vec<String> {
        self.jobs
            .iter()
            .enumerate()
            .map(|(index, job)| {
                let marker = self.marker(index);
                let command = if job.state == JobState::Running {
                    format!("{cmd} &", cmd = job.command)
                } else {
                    job.command.clone()
                };
                format!(
                    "[{id}]{marker}  {state:<7}  {command}",
                    id = job.id,
                    state = job.state.label(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> JobTable {
        JobTable::new()
            .with(Job::new(1, 100, JobState::Running, "sleep 100"))
            .with(Job::new(2, 200, JobState::Stopped, "vim notes.txt"))
            .with(Job::new(3, 300, JobState::Running, "make -j8"))
    }

    #[test]
    fn markers_flag_current_and_previous() {
        let t = table();
        assert_eq!(t.marker(0), ' ');
        assert_eq!(t.marker(1), '-'); // previous
        assert_eq!(t.marker(2), '+'); // current
    }

    #[test]
    fn list_lines_shell_shape() {
        let lines = table().list_lines();
        assert_eq!(
            lines,
            [
                "[1]   Running  sleep 100 &",
                "[2]-  Stopped  vim notes.txt",
                "[3]+  Running  make -j8 &",
            ]
        );
    }

    #[test]
    fn running_job_gets_ampersand_suffix() {
        let lines = JobTable::new()
            .with(Job::new(1, 10, JobState::Running, "server"))
            .list_lines();
        assert_eq!(lines, ["[1]+  Running  server &"]);
    }

    #[test]
    fn stopped_and_done_have_no_ampersand() {
        let lines = JobTable::new()
            .with(Job::new(1, 10, JobState::Done, "build"))
            .with(Job::new(2, 20, JobState::Stopped, "edit"))
            .list_lines();
        assert_eq!(lines, ["[1]-  Done     build", "[2]+  Stopped  edit"]);
    }

    #[test]
    fn empty_table_lists_nothing() {
        let t = JobTable::new();
        assert!(t.is_empty());
        assert!(t.list_lines().is_empty());
    }

    #[test]
    fn single_job_is_current() {
        let t = JobTable::new().with(Job::new(1, 5, JobState::Running, "x"));
        assert_eq!(t.marker(0), '+');
    }
}

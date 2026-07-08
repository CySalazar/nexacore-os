//! Per-agent computational budget tracking and enforcement.
//!
//! Each agent has a finite budget of tokens, compute time, and memory.
//! Exceeding the budget triggers a graceful termination of the agent's
//! current operation. Budget tracking is per-agent, so the Guidance
//! Agent's explanation token budget does not compete with the SysAdmin
//! Agent's operation budget.
//!
//! See NCIP-Agent-Arch-022 §S1.1 and `docs/10-glossary.md`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Computational budget for a single agent.
///
/// All fields are hard limits. When any limit is reached, the agent's
/// current operation is interrupted and a budget-exhaustion event is
/// emitted to the audit log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Budget {
    /// Maximum number of LLM tokens this agent may consume per session.
    pub max_tokens: u64,
    /// Tokens consumed so far in the current session.
    pub tokens_used: u64,
    /// Maximum wall-clock compute time per operation.
    pub max_compute_time: Duration,
    /// Maximum memory (in bytes) this agent's sandbox may allocate.
    pub max_memory_bytes: u64,
    /// Memory currently allocated (reported by sandbox).
    pub memory_used_bytes: u64,
}

impl Budget {
    /// Create a budget with the given limits and zero usage.
    #[must_use]
    pub fn new(max_tokens: u64, max_compute_time: Duration, max_memory_bytes: u64) -> Self {
        Self {
            max_tokens,
            tokens_used: 0,
            max_compute_time,
            max_memory_bytes,
            memory_used_bytes: 0,
        }
    }

    /// Returns `true` if the token budget is exhausted.
    #[must_use]
    pub fn tokens_exhausted(&self) -> bool {
        self.tokens_used >= self.max_tokens
    }

    /// Returns `true` if the memory budget is exhausted.
    #[must_use]
    pub fn memory_exhausted(&self) -> bool {
        self.memory_used_bytes >= self.max_memory_bytes
    }

    /// Returns the fraction of the token budget consumed (0.0 to 1.0+).
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // ratio only needs approximate display
    pub fn token_usage_ratio(&self) -> f64 {
        if self.max_tokens == 0 {
            return 1.0;
        }
        #[allow(clippy::float_arithmetic)]
        {
            self.tokens_used as f64 / self.max_tokens as f64
        }
    }

    /// Consume `n` tokens from the budget.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetExhausted::Tokens`] if the budget would be exceeded.
    pub fn consume_tokens(&mut self, n: u64) -> Result<(), BudgetExhausted> {
        let new_total = self.tokens_used.saturating_add(n);
        if new_total > self.max_tokens {
            return Err(BudgetExhausted::Tokens {
                requested: n,
                remaining: self.max_tokens.saturating_sub(self.tokens_used),
            });
        }
        self.tokens_used = new_total;
        Ok(())
    }

    /// Record memory allocation.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetExhausted::Memory`] if the memory budget would be exceeded.
    pub fn allocate_memory(&mut self, bytes: u64) -> Result<(), BudgetExhausted> {
        let new_total = self.memory_used_bytes.saturating_add(bytes);
        if new_total > self.max_memory_bytes {
            return Err(BudgetExhausted::Memory {
                requested: bytes,
                remaining: self.max_memory_bytes.saturating_sub(self.memory_used_bytes),
            });
        }
        self.memory_used_bytes = new_total;
        Ok(())
    }

    /// Release previously allocated memory.
    pub fn release_memory(&mut self, bytes: u64) {
        self.memory_used_bytes = self.memory_used_bytes.saturating_sub(bytes);
    }

    /// Reset token usage to zero (e.g., on session boundary).
    pub fn reset_tokens(&mut self) {
        self.tokens_used = 0;
    }

    /// Default budget for the Orchestrator agent.
    #[must_use]
    pub fn orchestrator_default() -> Self {
        Self::new(
            100_000,
            Duration::from_secs(30),
            64 * 1024 * 1024, // 64 MiB
        )
    }

    /// Default budget for the Guidance agent.
    #[must_use]
    pub fn guidance_default() -> Self {
        Self::new(
            500_000,
            Duration::from_secs(120),
            128 * 1024 * 1024, // 128 MiB
        )
    }

    /// Default budget for the `SysAdmin` agent.
    #[must_use]
    pub fn sysadmin_default() -> Self {
        Self::new(
            200_000,
            Duration::from_secs(300),
            256 * 1024 * 1024, // 256 MiB
        )
    }

    /// Default budget for the Task agent.
    #[must_use]
    pub fn task_default() -> Self {
        Self::new(
            400_000,
            Duration::from_secs(600), // long-running tasks
            256 * 1024 * 1024,        // 256 MiB
        )
    }

    /// Default budget for the Security agent.
    #[must_use]
    pub fn security_default() -> Self {
        Self::new(
            300_000,
            Duration::from_secs(60),
            128 * 1024 * 1024, // 128 MiB
        )
    }
}

/// Error returned when an agent exceeds its budget.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BudgetExhausted {
    /// Token budget exceeded.
    #[error("token budget exceeded: requested {requested}, remaining {remaining}")]
    Tokens {
        /// Tokens requested.
        requested: u64,
        /// Tokens remaining.
        remaining: u64,
    },
    /// Memory budget exceeded.
    #[error("memory budget exceeded: requested {requested} bytes, remaining {remaining} bytes")]
    Memory {
        /// Bytes requested.
        requested: u64,
        /// Bytes remaining.
        remaining: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_budget_has_zero_usage() {
        let b = Budget::new(1000, Duration::from_secs(10), 1024);
        assert_eq!(b.tokens_used, 0);
        assert_eq!(b.memory_used_bytes, 0);
        assert!(!b.tokens_exhausted());
        assert!(!b.memory_exhausted());
    }

    #[test]
    fn consume_tokens_within_budget() {
        let mut b = Budget::new(100, Duration::from_secs(1), 1024);
        b.consume_tokens(50).unwrap();
        assert_eq!(b.tokens_used, 50);
        b.consume_tokens(50).unwrap();
        assert!(b.tokens_exhausted());
    }

    #[test]
    fn consume_tokens_exceeds_budget() {
        let mut b = Budget::new(100, Duration::from_secs(1), 1024);
        b.consume_tokens(50).unwrap();
        let err = b.consume_tokens(60).unwrap_err();
        assert_eq!(
            err,
            BudgetExhausted::Tokens {
                requested: 60,
                remaining: 50
            }
        );
    }

    #[test]
    fn allocate_memory_within_budget() {
        let mut b = Budget::new(100, Duration::from_secs(1), 1024);
        b.allocate_memory(512).unwrap();
        assert_eq!(b.memory_used_bytes, 512);
    }

    #[test]
    fn allocate_memory_exceeds_budget() {
        let mut b = Budget::new(100, Duration::from_secs(1), 1024);
        b.allocate_memory(512).unwrap();
        let err = b.allocate_memory(600).unwrap_err();
        assert_eq!(
            err,
            BudgetExhausted::Memory {
                requested: 600,
                remaining: 512
            }
        );
    }

    #[test]
    fn release_memory() {
        let mut b = Budget::new(100, Duration::from_secs(1), 1024);
        b.allocate_memory(512).unwrap();
        b.release_memory(256);
        assert_eq!(b.memory_used_bytes, 256);
    }

    #[test]
    fn release_memory_saturates_at_zero() {
        let mut b = Budget::new(100, Duration::from_secs(1), 1024);
        b.allocate_memory(100).unwrap();
        b.release_memory(200);
        assert_eq!(b.memory_used_bytes, 0);
    }

    #[test]
    fn reset_tokens() {
        let mut b = Budget::new(100, Duration::from_secs(1), 1024);
        b.consume_tokens(100).unwrap();
        assert!(b.tokens_exhausted());
        b.reset_tokens();
        assert!(!b.tokens_exhausted());
    }

    #[test]
    fn token_usage_ratio() {
        let mut b = Budget::new(100, Duration::from_secs(1), 1024);
        assert!((b.token_usage_ratio() - 0.0).abs() < f64::EPSILON);
        b.consume_tokens(50).unwrap();
        assert!((b.token_usage_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn token_usage_ratio_zero_max() {
        let b = Budget::new(0, Duration::from_secs(1), 1024);
        assert!((b.token_usage_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn default_budgets_are_valid() {
        let budgets = [
            Budget::orchestrator_default(),
            Budget::guidance_default(),
            Budget::sysadmin_default(),
            Budget::security_default(),
        ];
        for b in &budgets {
            assert!(b.max_tokens > 0);
            assert!(b.max_memory_bytes > 0);
            assert!(!b.max_compute_time.is_zero());
        }
    }
}

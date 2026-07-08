//! Local reputation scoring (WS6-07.5).
//!
//! Each node scores its peers locally from the outcomes of the workloads it has
//! delegated to them. The score drives hop selection (WS6-07.10) and expert
//! placement decisions: a peer that reliably returns correct results is
//! preferred; one that fails, or — worse — returns results that disagree with
//! the redundant quorum (WS6-05.8), is avoided.
//!
//! # The model
//!
//! Reputation is a **Beta-reputation** posterior. A peer accumulates positive
//! evidence (successes) and negative evidence (failures and divergences); the
//! score is the posterior mean of a Beta distribution,
//!
//! ```text
//! score = (positives + prior_pos) / (positives + negatives + prior_pos + prior_neg)
//! ```
//!
//! with `negatives = failures + divergence_weight * divergences`. The
//! `Beta(prior_pos, prior_neg)` prior makes a brand-new peer start at a neutral
//! `0.5` (with the default symmetric prior) rather than at either extreme, so a
//! single observation cannot swing trust wildly. A **divergence** (a wrong
//! result, detected by redundancy) counts as several failures
//! (`divergence_weight`), because returning plausible-but-wrong output is more
//! damaging than simply failing to answer.
//!
//! This module defines the scoring model and the per-peer accumulator; feeding
//! actual workload outcomes into a fleet of peers (and aging old evidence) is
//! the reputation-update task (WS6-07.6).

// Reputation is an inherently fractional quantity (a probability in `[0, 1]`);
// the scoring arithmetic is floating point by nature, like the other numeric
// modules in the workspace.
#![allow(clippy::float_arithmetic)]

use std::collections::HashMap;

use crate::discovery::NodeId;

/// The outcome of a workload delegated to a peer, as it affects reputation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The peer returned a correct result on time.
    Success,
    /// The peer failed to return a result (timeout, error, disconnect).
    Failure,
    /// The peer returned a result that disagreed with the redundant quorum
    /// (WS6-05.8) — a wrong answer, the most damaging outcome.
    Divergence,
}

/// Parameters of the Beta-reputation scoring model (WS6-07.5).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReputationModel {
    /// How many units of negative evidence one [`Outcome::Divergence`] adds,
    /// relative to one [`Outcome::Failure`] (which adds 1). `>= 1`.
    pub divergence_weight: f64,
    /// Prior positive evidence (Beta α). With the default symmetric prior a new
    /// peer scores `0.5`.
    pub prior_positive: f64,
    /// Prior negative evidence (Beta β).
    pub prior_negative: f64,
}

impl ReputationModel {
    /// Construct a model with explicit parameters.
    #[must_use]
    pub const fn new(divergence_weight: f64, prior_positive: f64, prior_negative: f64) -> Self {
        Self {
            divergence_weight,
            prior_positive,
            prior_negative,
        }
    }
}

impl Default for ReputationModel {
    /// A divergence weighted as 3 failures, with a symmetric `Beta(1, 1)` prior
    /// (new peers start neutral at `0.5`).
    fn default() -> Self {
        Self::new(3.0, 1.0, 1.0)
    }
}

/// A peer's accumulated reputation evidence (WS6-07.5).
///
/// Counts are saturating, so a long-lived peer cannot overflow them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Reputation {
    /// Number of successful workloads.
    pub successes: u32,
    /// Number of failed workloads.
    pub failures: u32,
    /// Number of divergent (wrong-result) workloads.
    pub divergences: u32,
}

impl Reputation {
    /// An accumulator with no evidence.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            successes: 0,
            failures: 0,
            divergences: 0,
        }
    }

    /// Fold one workload `outcome` into the accumulator.
    pub fn record(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Success => self.successes = self.successes.saturating_add(1),
            Outcome::Failure => self.failures = self.failures.saturating_add(1),
            Outcome::Divergence => self.divergences = self.divergences.saturating_add(1),
        }
    }

    /// The total number of recorded observations.
    #[must_use]
    pub fn observations(&self) -> u32 {
        self.successes
            .saturating_add(self.failures)
            .saturating_add(self.divergences)
    }

    /// The reputation score in `[0, 1]` under `model` (the Beta posterior mean).
    /// Higher is more trustworthy.
    #[must_use]
    pub fn score(&self, model: &ReputationModel) -> f64 {
        let positives = f64::from(self.successes);
        let negatives =
            f64::from(self.divergences).mul_add(model.divergence_weight, f64::from(self.failures));
        let numerator = positives + model.prior_positive;
        let denominator = positives + negatives + model.prior_positive + model.prior_negative;
        numerator / denominator
    }

    /// Whether the peer's score is at least `threshold` under `model`.
    #[must_use]
    pub fn is_trusted(&self, model: &ReputationModel, threshold: f64) -> bool {
        self.score(model) >= threshold
    }
}

/// A per-node reputation registry that ingests workload outcomes (WS6-07.6).
///
/// Holds one [`Reputation`] accumulator per peer plus the [`ReputationModel`]
/// used to score them. [`observe`](ReputationBook::observe) is the update path —
/// the mesh runtime calls it with the outcome of each delegated workload — and
/// [`ranked`](ReputationBook::ranked) orders peers by trust for hop/expert
/// selection. [`decay`](ReputationBook::decay) ages old evidence so reputation
/// tracks recent behaviour and a reformed peer can recover.
#[derive(Debug, Clone, Default)]
pub struct ReputationBook {
    model: ReputationModel,
    peers: HashMap<NodeId, Reputation>,
}

impl ReputationBook {
    /// A book using the default [`ReputationModel`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A book using an explicit scoring model.
    #[must_use]
    pub fn with_model(model: ReputationModel) -> Self {
        Self {
            model,
            peers: HashMap::new(),
        }
    }

    /// The scoring model in use.
    #[must_use]
    pub const fn model(&self) -> &ReputationModel {
        &self.model
    }

    /// Record a workload `outcome` for `node`, creating its accumulator on first
    /// observation.
    pub fn observe(&mut self, node: NodeId, outcome: Outcome) {
        self.peers.entry(node).or_default().record(outcome);
    }

    /// The accumulated reputation for `node` (a neutral default if unseen).
    #[must_use]
    pub fn reputation(&self, node: &NodeId) -> Reputation {
        self.peers.get(node).copied().unwrap_or_default()
    }

    /// The score for `node` under the book's model (neutral `0.5` if unseen).
    #[must_use]
    pub fn score(&self, node: &NodeId) -> f64 {
        self.reputation(node).score(&self.model)
    }

    /// Whether `node` scores at least `threshold`.
    #[must_use]
    pub fn is_trusted(&self, node: &NodeId, threshold: f64) -> bool {
        self.score(node) >= threshold
    }

    /// The number of peers with recorded evidence.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether no peer has any recorded evidence.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// All known peers paired with their score, most trustworthy first.
    #[must_use]
    pub fn ranked(&self) -> Vec<(NodeId, f64)> {
        let mut scored: Vec<(NodeId, f64)> = self
            .peers
            .iter()
            .map(|(id, rep)| (*id, rep.score(&self.model)))
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        scored
    }

    /// Age every peer's evidence by multiplying its counts by `factor`
    /// (clamped to `[0, 1]`), so old observations fade and recent behaviour
    /// dominates. A `factor` of `1.0` is a no-op; `0.5` halves all evidence.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn decay(&mut self, factor: f64) {
        let f = factor.clamp(0.0, 1.0);
        for rep in self.peers.values_mut() {
            // Each product is in `[0, count]`, non-negative and within u32, so
            // the truncating cast is the intended floor.
            rep.successes = (f64::from(rep.successes) * f) as u32;
            rep.failures = (f64::from(rep.failures) * f) as u32;
            rep.divergences = (f64::from(rep.divergences) * f) as u32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absolute tolerance for floating-point score comparisons.
    const EPS: f64 = 1e-9;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < EPS
    }

    #[test]
    fn a_fresh_peer_is_neutral() {
        let rep = Reputation::new();
        assert!(close(rep.score(&ReputationModel::default()), 0.5));
        assert_eq!(rep.observations(), 0);
    }

    #[test]
    fn record_accumulates_counts() {
        let mut rep = Reputation::new();
        rep.record(Outcome::Success);
        rep.record(Outcome::Success);
        rep.record(Outcome::Failure);
        rep.record(Outcome::Divergence);
        assert_eq!(rep.successes, 2);
        assert_eq!(rep.failures, 1);
        assert_eq!(rep.divergences, 1);
        assert_eq!(rep.observations(), 4);
    }

    #[test]
    fn successes_raise_the_score() {
        let model = ReputationModel::default();
        let mut rep = Reputation::new();
        for _ in 0..3 {
            rep.record(Outcome::Success);
        }
        // (3 + 1) / (3 + 0 + 1 + 1) = 4/5 = 0.8.
        assert!(close(rep.score(&model), 0.8));
        assert!(rep.score(&model) > 0.5);
    }

    #[test]
    fn failures_lower_the_score_below_neutral() {
        let model = ReputationModel::default();
        let mut rep = Reputation::new();
        rep.record(Outcome::Failure);
        rep.record(Outcome::Failure);
        // (0 + 1) / (0 + 2 + 1 + 1) = 1/4 = 0.25.
        assert!(close(rep.score(&model), 0.25));
        assert!(rep.score(&model) < 0.5);
    }

    #[test]
    fn a_divergence_is_penalised_more_than_a_failure() {
        let model = ReputationModel::default();
        let mut with_failure = Reputation::new();
        with_failure.record(Outcome::Failure);
        let mut with_divergence = Reputation::new();
        with_divergence.record(Outcome::Divergence);
        assert!(with_divergence.score(&model) < with_failure.score(&model));
        // Divergence counts as 3 failures: (0+1)/(0+3+1+1) = 1/5 = 0.2.
        assert!(close(with_divergence.score(&model), 0.2));
    }

    #[test]
    fn is_trusted_applies_the_threshold() {
        let model = ReputationModel::default();
        let mut rep = Reputation::new();
        for _ in 0..10 {
            rep.record(Outcome::Success);
        }
        assert!(rep.is_trusted(&model, 0.8));
        assert!(!rep.is_trusted(&model, 0.99));
    }

    #[test]
    fn divergence_weight_is_configurable() {
        // A harsher model penalises divergences more steeply.
        let lenient = ReputationModel::new(1.0, 1.0, 1.0);
        let harsh = ReputationModel::new(10.0, 1.0, 1.0);
        let mut rep = Reputation::new();
        rep.record(Outcome::Divergence);
        assert!(rep.score(&harsh) < rep.score(&lenient));
    }

    // --- Reputation book / outcome updates (WS6-07.6) -----------------------

    fn node(tag: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        if let Some(first) = bytes.first_mut() {
            *first = tag;
        }
        NodeId::from_bytes(bytes)
    }

    #[test]
    fn new_book_is_empty_and_scores_unknown_peers_neutral() {
        let book = ReputationBook::new();
        assert!(book.is_empty());
        assert_eq!(book.len(), 0);
        assert!(close(book.score(&node(1)), 0.5));
        assert_eq!(book.reputation(&node(1)), Reputation::new());
    }

    #[test]
    fn observe_updates_a_peers_reputation() {
        let mut book = ReputationBook::new();
        book.observe(node(1), Outcome::Success);
        book.observe(node(1), Outcome::Success);
        book.observe(node(1), Outcome::Failure);
        assert_eq!(book.len(), 1);
        let rep = book.reputation(&node(1));
        assert_eq!(rep.successes, 2);
        assert_eq!(rep.failures, 1);
        // (2 + 1) / (2 + 1 + 1 + 1) = 3/5 = 0.6.
        assert!(close(book.score(&node(1)), 0.6));
    }

    #[test]
    fn ranked_orders_peers_most_trustworthy_first() {
        let mut book = ReputationBook::new();
        // good: all successes; bad: a divergence.
        for _ in 0..5 {
            book.observe(node(1), Outcome::Success);
        }
        book.observe(node(2), Outcome::Divergence);
        let ranked = book.ranked();
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked.first().map(|(id, _)| *id), Some(node(1)));
        assert_eq!(ranked.last().map(|(id, _)| *id), Some(node(2)));
    }

    #[test]
    fn is_trusted_uses_the_books_model() {
        let mut book = ReputationBook::new();
        for _ in 0..10 {
            book.observe(node(1), Outcome::Success);
        }
        assert!(book.is_trusted(&node(1), 0.8));
        assert!(!book.is_trusted(&node(1), 0.99));
    }

    #[test]
    fn decay_ages_evidence_toward_neutral() {
        let mut book = ReputationBook::new();
        for _ in 0..10 {
            book.observe(node(1), Outcome::Success);
        }
        let before = book.score(&node(1));
        book.decay(0.5);
        let rep = book.reputation(&node(1));
        assert_eq!(rep.successes, 5); // 10 * 0.5
        // Halving the evidence pulls the score back toward the 0.5 prior.
        assert!(book.score(&node(1)) < before);
        assert!(book.score(&node(1)) > 0.5);
    }

    #[test]
    fn decay_factor_is_clamped() {
        let mut book = ReputationBook::new();
        book.observe(node(1), Outcome::Success);
        // Out-of-range factors are clamped to [0, 1]; 1.0 (from 2.0) is a no-op.
        book.decay(2.0);
        assert_eq!(book.reputation(&node(1)).successes, 1);
        // 0.0 (from -1.0) erases evidence.
        book.decay(-1.0);
        assert_eq!(book.reputation(&node(1)).successes, 0);
    }
}

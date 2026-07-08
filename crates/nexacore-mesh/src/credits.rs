//! Compute credit ledger (gossip-replicated, signed) — WS6-07.
//!
//! This module defines the **signed compute credit transaction** (WS6-07.1):
//! the record one node issues to credit another for compute work performed.
//! The append-only ledger (WS6-07.2), its gossip replication (WS6-07.3), and
//! double-spend reconciliation (WS6-07.4) build on the [`SignedCreditTx`]
//! established here.
//!
//! # Identity binding
//!
//! A node's [`NodeId`] is the [`domain_separated_hash`] of its identity
//! (verifying) key — see [`crate::discovery`]. A [`SignedCreditTx`] therefore
//! carries the signer's verifying key inline and [`verify`](SignedCreditTx::verify)
//! checks that the transaction's `from` id equals
//! [`NodeId::from_key_material`] of that key. This binds the signature to the
//! debited identity: a node cannot issue a transaction debiting an id it does
//! not control, because it would have to forge a key whose hash is that id.
//!
//! # Wire format
//!
//! As with the rest of the mesh, the on-the-wire encoding is added with the
//! transport (WS6-04.6) under the serialization NCIP, so no serde derives are
//! committed here. [`CreditTx::signing_bytes`] is the canonical,
//! domain-separated byte layout the signature covers and is stable.
//!
//! [`domain_separated_hash`]: nexacore_crypto::hash::domain_separated_hash

use std::collections::HashMap;

use nexacore_crypto::{
    hash::{HASH_LEN, domain_separated_hash},
    signing::{
        NexaCoreSignature, NexaCoreSigningKey, NexaCoreVerifyingKey, SIGNATURE_LEN,
        VERIFYING_KEY_LEN,
    },
};

use crate::discovery::NodeId;

/// Domain tag separating credit-transaction signing bytes from any other
/// signed message in NexaCore OS (terminated by a `0x00` so it cannot be a prefix
/// of the fields that follow).
const CREDIT_TX_DOMAIN: &[u8] = b"nexacore-mesh::credit-tx::v1\x00";

/// Hash domain for a transaction's content digest, used to detect double-spends
/// (two distinct transactions sharing one `(from, nonce)`).
const CREDIT_TX_DIGEST_DOMAIN: &str = "nexacore-mesh::credit-tx::digest::v1";

/// An unsigned compute credit transaction: `from` credits `to` with `amount`
/// credits for compute work (WS6-07.1).
///
/// `nonce` is monotonic per `from` and, together with the append-only ledger
/// (WS6-07.2), is what anti-double-spend reconciliation (WS6-07.4) keys on.
/// `timestamp` is caller-supplied (milliseconds) so the schema stays
/// deterministic and clock-source agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CreditTx {
    /// The debited node (the payer), which signs the transaction.
    pub from: NodeId,
    /// The credited node (the payee).
    pub to: NodeId,
    /// The number of credits transferred.
    pub amount: u64,
    /// Per-`from` monotonic counter (replay / double-count guard).
    pub nonce: u64,
    /// Caller-supplied issue time in milliseconds.
    pub timestamp: u64,
}

impl CreditTx {
    /// Create a transaction.
    #[must_use]
    pub const fn new(from: NodeId, to: NodeId, amount: u64, nonce: u64, timestamp: u64) -> Self {
        Self {
            from,
            to,
            amount,
            nonce,
            timestamp,
        }
    }

    /// The canonical, domain-separated bytes the signature covers.
    ///
    /// Layout: `CREDIT_TX_DOMAIN || from || to || amount || nonce ||
    /// timestamp`, with the three integers little-endian. Stable across
    /// versions of this crate.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(CREDIT_TX_DOMAIN.len() + (2 * 32) + (3 * 8));
        buf.extend_from_slice(CREDIT_TX_DOMAIN);
        buf.extend_from_slice(self.from.as_bytes());
        buf.extend_from_slice(self.to.as_bytes());
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf
    }

    /// A content digest of this transaction (a `BLAKE3` domain-separated hash of
    /// [`signing_bytes`](CreditTx::signing_bytes)).
    ///
    /// Two transactions are content-equal iff their digests match; the ledger
    /// uses this to tell a benign replay (same `(from, nonce)`, same digest)
    /// from a double-spend (same `(from, nonce)`, different digest).
    #[must_use]
    pub fn digest(&self) -> [u8; HASH_LEN] {
        domain_separated_hash(CREDIT_TX_DIGEST_DOMAIN, &self.signing_bytes())
    }

    /// Sign this transaction with the payer's identity key, producing a
    /// [`SignedCreditTx`] that carries the verifying key and signature.
    ///
    /// The caller is responsible for ensuring `self.from` is the [`NodeId`]
    /// derived from `key`'s verifying key; [`SignedCreditTx::verify`] rejects
    /// any mismatch.
    #[must_use]
    pub fn sign(&self, key: &NexaCoreSigningKey) -> SignedCreditTx {
        let signature = key.sign(&self.signing_bytes());
        SignedCreditTx {
            tx: *self,
            signer_key: key.verifying_key().as_bytes(),
            signature: signature.to_bytes(),
        }
    }
}

/// Why a [`SignedCreditTx`] failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CreditError {
    /// The embedded signer verifying key is not a valid key.
    #[error("signer verifying key is malformed")]
    InvalidKey,
    /// The transaction's `from` id is not the hash of the signer key — the
    /// signature does not authorise debiting that identity.
    #[error("transaction `from` id does not match the signer key")]
    IdMismatch,
    /// The signature does not match the transaction under the signer key.
    #[error("signature verification failed")]
    BadSignature,
}

/// A [`CreditTx`] together with the payer's verifying key and signature
/// (WS6-07.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedCreditTx {
    tx: CreditTx,
    signer_key: [u8; VERIFYING_KEY_LEN],
    signature: [u8; SIGNATURE_LEN],
}

impl SignedCreditTx {
    /// The underlying transaction.
    #[must_use]
    pub const fn tx(&self) -> &CreditTx {
        &self.tx
    }

    /// The payer's verifying key bytes.
    #[must_use]
    pub const fn signer_key(&self) -> &[u8; VERIFYING_KEY_LEN] {
        &self.signer_key
    }

    /// The signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// Verify the transaction: the signer key must be valid, the `from` id must
    /// be the hash of that key (identity binding), and the signature must match
    /// the canonical [`CreditTx::signing_bytes`].
    ///
    /// # Errors
    ///
    /// Returns the [`CreditError`] describing the first check that failed.
    pub fn verify(&self) -> Result<(), CreditError> {
        let key = NexaCoreVerifyingKey::from_bytes(&self.signer_key)
            .map_err(|_| CreditError::InvalidKey)?;
        if self.tx.from != NodeId::from_key_material(&self.signer_key) {
            return Err(CreditError::IdMismatch);
        }
        let signature = NexaCoreSignature::from_bytes(self.signature);
        key.verify(&self.tx.signing_bytes(), &signature)
            .map_err(|_| CreditError::BadSignature)
    }
}

/// Why appending a [`SignedCreditTx`] to a [`CreditLedger`] was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    /// The transaction failed cryptographic verification.
    #[error("invalid transaction: {0}")]
    Invalid(#[from] CreditError),
    /// The transaction's nonce is not newer than the last one accepted from the
    /// same payer (a replay or a reordering).
    #[error("stale nonce {got}: at least {expected_min} required for this payer")]
    StaleNonce {
        /// The smallest nonce that would be accepted next for this payer.
        expected_min: u64,
        /// The nonce the rejected transaction carried.
        got: u64,
    },
}

/// A detected double-spend: a payer that signed two distinct transactions
/// sharing one `(payer, nonce)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoubleSpend {
    /// The forking payer.
    pub payer: NodeId,
    /// The nonce that was reused with conflicting content.
    pub nonce: u64,
}

/// The outcome of [`CreditLedger::reconcile`] over a batch of foreign
/// transactions (WS6-07.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Newly accepted transactions.
    pub applied: usize,
    /// Transactions already present with identical content (idempotent).
    pub duplicates: usize,
    /// Detected double-spends (conflicting transactions, not applied).
    pub double_spends: Vec<DoubleSpend>,
    /// Transactions that failed verification.
    pub rejected: usize,
}

/// An append-only, signature-verified compute credit ledger (WS6-07.2).
///
/// Every [`append`](CreditLedger::append)ed transaction is
/// [`verify`](SignedCreditTx::verify)ied and must carry a nonce strictly
/// greater than the last accepted from the same payer, so replays and
/// reorderings are rejected at the door. Per-node net balances are maintained
/// incrementally (a transaction debits `from` and credits `to`).
///
/// This is the local, single-replica ledger. Gossip replication (WS6-07.3) and
/// cross-replica double-spend reconciliation (WS6-07.4) build on it.
#[derive(Debug, Clone, Default)]
pub struct CreditLedger {
    entries: Vec<SignedCreditTx>,
    last_nonce: HashMap<NodeId, u64>,
    balances: HashMap<NodeId, i128>,
    /// Content digest accepted for each `(payer, nonce)`, used to distinguish a
    /// benign replay from a double-spend during reconciliation (WS6-07.4).
    nonce_digest: HashMap<(NodeId, u64), [u8; HASH_LEN]>,
}

impl CreditLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify and append a transaction.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::Invalid`] if the signature or identity binding is
    /// bad, or [`LedgerError::StaleNonce`] if the nonce does not advance the
    /// payer's sequence. On any error the ledger is left unchanged.
    pub fn append(&mut self, signed: SignedCreditTx) -> Result<(), LedgerError> {
        signed.verify()?;
        let from = signed.tx().from;
        let nonce = signed.tx().nonce;
        if let Some(&last) = self.last_nonce.get(&from) {
            if nonce <= last {
                return Err(LedgerError::StaleNonce {
                    expected_min: last.saturating_add(1),
                    got: nonce,
                });
            }
        }
        self.last_nonce.insert(from, nonce);
        self.apply_entry(signed);
        Ok(())
    }

    /// Apply an already-verified, conflict-free transaction: update balances,
    /// record its `(payer, nonce)` digest, and append it.
    fn apply_entry(&mut self, signed: SignedCreditTx) {
        let tx = *signed.tx();
        let amount = i128::from(tx.amount);
        *self.balances.entry(tx.from).or_insert(0) -= amount;
        *self.balances.entry(tx.to).or_insert(0) += amount;
        self.nonce_digest.insert((tx.from, tx.nonce), tx.digest());
        self.entries.push(signed);
    }

    /// Reconcile a batch of transactions received from a peer replica into this
    /// ledger (WS6-07.4).
    ///
    /// Each foreign transaction is verified, then classified by its
    /// `(payer, nonce)`:
    ///
    /// - **new** — accepted and applied (tolerant of out-of-order arrival and
    ///   gaps, unlike the strict single-writer [`append`](CreditLedger::append));
    /// - **duplicate** — already present with the same content digest, ignored
    ///   idempotently;
    /// - **double-spend** — already present with a *different* digest (the payer
    ///   forked its sequence), recorded in the report and **not** applied;
    /// - **rejected** — failed signature/identity verification.
    ///
    /// Returns a [`ReconcileReport`] summarising the batch.
    pub fn reconcile(&mut self, foreign: &[SignedCreditTx]) -> ReconcileReport {
        let mut report = ReconcileReport::default();
        for signed in foreign {
            if signed.verify().is_err() {
                report.rejected += 1;
                continue;
            }
            let from = signed.tx().from;
            let nonce = signed.tx().nonce;
            let digest = signed.tx().digest();
            match self.nonce_digest.get(&(from, nonce)).copied() {
                Some(existing) if existing == digest => report.duplicates += 1,
                Some(_) => report
                    .double_spends
                    .push(DoubleSpend { payer: from, nonce }),
                None => {
                    let new_last = self
                        .last_nonce
                        .get(&from)
                        .copied()
                        .map_or(nonce, |last| last.max(nonce));
                    self.last_nonce.insert(from, new_last);
                    self.apply_entry(*signed);
                    report.applied += 1;
                }
            }
        }
        report
    }

    /// The verified transactions in append order.
    #[must_use]
    pub fn entries(&self) -> &[SignedCreditTx] {
        &self.entries
    }

    /// The number of transactions recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ledger is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The net credit balance of `node` (credits received minus issued); 0 if
    /// the node has never appeared in a transaction.
    #[must_use]
    pub fn balance(&self, node: &NodeId) -> i128 {
        self.balances.get(node).copied().unwrap_or(0)
    }

    /// The highest nonce accepted from `node`, if any.
    #[must_use]
    pub fn last_nonce(&self, node: &NodeId) -> Option<u64> {
        self.last_nonce.get(node).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signing key plus the `NodeId` correctly bound to its verifying key.
    fn keyed_node() -> (NexaCoreSigningKey, NodeId) {
        let key = NexaCoreSigningKey::generate();
        let id = NodeId::from_key_material(&key.verifying_key().as_bytes());
        (key, id)
    }

    #[test]
    fn signing_bytes_are_domain_separated_and_sized() {
        let tx = CreditTx::new(NodeId::ZERO, NodeId::ZERO, 1, 2, 3);
        let bytes = tx.signing_bytes();
        assert!(bytes.starts_with(CREDIT_TX_DOMAIN));
        assert_eq!(bytes.len(), CREDIT_TX_DOMAIN.len() + 64 + 24);
    }

    #[test]
    fn signed_transaction_verifies() {
        let (key, from) = keyed_node();
        let (_, to) = keyed_node();
        let tx = CreditTx::new(from, to, 100, 1, 1_700_000_000_000);
        let signed = tx.sign(&key);
        assert_eq!(signed.verify(), Ok(()));
        assert_eq!(signed.tx(), &tx);
    }

    #[test]
    fn tampering_with_the_amount_breaks_the_signature() {
        let (key, from) = keyed_node();
        let (_, to) = keyed_node();
        let mut signed = CreditTx::new(from, to, 100, 1, 0).sign(&key);
        // Forge a larger amount after signing.
        signed.tx.amount = 1_000_000;
        assert_eq!(signed.verify(), Err(CreditError::BadSignature));
    }

    #[test]
    fn from_id_not_matching_the_signer_key_is_rejected() {
        let (key, _real_id) = keyed_node();
        // Claim a `from` id the signer does not control.
        let tx = CreditTx::new(NodeId::ZERO, NodeId::ZERO, 50, 7, 0);
        let signed = tx.sign(&key);
        assert_eq!(signed.verify(), Err(CreditError::IdMismatch));
    }

    #[test]
    fn a_different_signer_cannot_forge_anothers_debit() {
        let (alice_key, alice_id) = keyed_node();
        let (mallory_key, _mallory_id) = keyed_node();
        let (_, bob_id) = keyed_node();
        // Mallory tries to debit Alice by signing a tx with `from = alice`.
        let tx = CreditTx::new(alice_id, bob_id, 9999, 1, 0);
        let forged = tx.sign(&mallory_key);
        // The embedded key is Mallory's, so the id binding fails.
        assert_eq!(forged.verify(), Err(CreditError::IdMismatch));
        // And a genuine signature from Alice over the same tx verifies.
        let genuine = tx.sign(&alice_key);
        assert_eq!(genuine.verify(), Ok(()));
    }

    // --- Append-only ledger (WS6-07.2) --------------------------------------

    #[test]
    fn new_ledger_is_empty() {
        let ledger = CreditLedger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
        assert_eq!(ledger.balance(&NodeId::ZERO), 0);
        assert_eq!(ledger.last_nonce(&NodeId::ZERO), None);
    }

    #[test]
    fn append_records_entry_and_updates_balances() {
        let (alice_key, alice) = keyed_node();
        let (_, bob) = keyed_node();
        let mut ledger = CreditLedger::new();
        assert_eq!(
            ledger.append(CreditTx::new(alice, bob, 100, 1, 0).sign(&alice_key)),
            Ok(())
        );
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.balance(&alice), -100);
        assert_eq!(ledger.balance(&bob), 100);
        assert_eq!(ledger.last_nonce(&alice), Some(1));
    }

    #[test]
    fn append_rejects_invalid_signature_and_leaves_ledger_unchanged() {
        let (alice_key, alice) = keyed_node();
        let (_, bob) = keyed_node();
        let mut signed = CreditTx::new(alice, bob, 100, 1, 0).sign(&alice_key);
        signed.tx.amount = 1; // break the signature
        let mut ledger = CreditLedger::new();
        assert_eq!(
            ledger.append(signed),
            Err(LedgerError::Invalid(CreditError::BadSignature))
        );
        assert!(ledger.is_empty());
        assert_eq!(ledger.balance(&alice), 0);
    }

    #[test]
    fn append_rejects_replayed_or_reordered_nonce() {
        let (alice_key, alice) = keyed_node();
        let (_, bob) = keyed_node();
        let mut ledger = CreditLedger::new();
        assert_eq!(
            ledger.append(CreditTx::new(alice, bob, 10, 5, 0).sign(&alice_key)),
            Ok(())
        );
        // Same nonce again → stale.
        assert_eq!(
            ledger.append(CreditTx::new(alice, bob, 10, 5, 0).sign(&alice_key)),
            Err(LedgerError::StaleNonce {
                expected_min: 6,
                got: 5,
            })
        );
        // A lower nonce → stale.
        assert_eq!(
            ledger.append(CreditTx::new(alice, bob, 10, 3, 0).sign(&alice_key)),
            Err(LedgerError::StaleNonce {
                expected_min: 6,
                got: 3,
            })
        );
        // Ledger unchanged by the rejects.
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.balance(&alice), -10);
    }

    #[test]
    fn nonces_advance_per_payer_and_are_independent_across_payers() {
        let (alice_key, alice) = keyed_node();
        let (bob_key, bob) = keyed_node();
        let (_, carol) = keyed_node();
        let mut ledger = CreditLedger::new();
        assert_eq!(
            ledger.append(CreditTx::new(alice, carol, 10, 1, 0).sign(&alice_key)),
            Ok(())
        );
        assert_eq!(
            ledger.append(CreditTx::new(alice, carol, 5, 2, 0).sign(&alice_key)),
            Ok(())
        );
        // Bob's nonce sequence is independent — nonce 1 is fine for Bob.
        assert_eq!(
            ledger.append(CreditTx::new(bob, carol, 7, 1, 0).sign(&bob_key)),
            Ok(())
        );
        assert_eq!(ledger.len(), 3);
        assert_eq!(ledger.balance(&alice), -15);
        assert_eq!(ledger.balance(&bob), -7);
        assert_eq!(ledger.balance(&carol), 22);
        assert_eq!(ledger.last_nonce(&alice), Some(2));
        assert_eq!(ledger.last_nonce(&bob), Some(1));
    }

    // --- Reconciliation / anti-double-spend (WS6-07.4) ----------------------

    #[test]
    fn reconcile_applies_new_foreign_entries() {
        let (alice_key, alice) = keyed_node();
        let (_, bob) = keyed_node();
        let foreign = vec![
            CreditTx::new(alice, bob, 10, 1, 0).sign(&alice_key),
            CreditTx::new(alice, bob, 20, 2, 0).sign(&alice_key),
        ];
        let mut ledger = CreditLedger::new();
        let report = ledger.reconcile(&foreign);
        assert_eq!(report.applied, 2);
        assert_eq!(report.duplicates, 0);
        assert!(report.double_spends.is_empty());
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.balance(&bob), 30);
    }

    #[test]
    fn reconcile_treats_identical_entries_as_idempotent_duplicates() {
        let (alice_key, alice) = keyed_node();
        let (_, bob) = keyed_node();
        let tx = CreditTx::new(alice, bob, 10, 1, 0).sign(&alice_key);
        let mut ledger = CreditLedger::new();
        assert_eq!(ledger.reconcile(&[tx]).applied, 1);
        // Re-delivering the same entry must not double-count.
        let report = ledger.reconcile(&[tx]);
        assert_eq!(report.applied, 0);
        assert_eq!(report.duplicates, 1);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.balance(&bob), 10);
    }

    #[test]
    fn reconcile_detects_a_double_spend() {
        let (alice_key, alice) = keyed_node();
        let (_, bob) = keyed_node();
        let (_, carol) = keyed_node();
        // Alice forks her nonce 1: one tx to Bob, a conflicting one to Carol.
        let to_bob = CreditTx::new(alice, bob, 10, 1, 0).sign(&alice_key);
        let to_carol = CreditTx::new(alice, carol, 20, 1, 0).sign(&alice_key);
        let mut ledger = CreditLedger::new();
        let report = ledger.reconcile(&[to_bob, to_carol]);
        assert_eq!(report.applied, 1);
        assert_eq!(
            report.double_spends,
            vec![DoubleSpend {
                payer: alice,
                nonce: 1
            }]
        );
        // Only the first of the conflicting pair was applied.
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.balance(&bob), 10);
        assert_eq!(ledger.balance(&carol), 0);
    }

    #[test]
    fn reconcile_rejects_invalid_entries() {
        let (alice_key, alice) = keyed_node();
        let (_, bob) = keyed_node();
        let mut tampered = CreditTx::new(alice, bob, 10, 1, 0).sign(&alice_key);
        tampered.tx.amount = 999;
        let mut ledger = CreditLedger::new();
        let report = ledger.reconcile(&[tampered]);
        assert_eq!(report.rejected, 1);
        assert_eq!(report.applied, 0);
        assert!(ledger.is_empty());
    }

    #[test]
    fn reconcile_tolerates_out_of_order_arrival() {
        let (alice_key, alice) = keyed_node();
        let (_, bob) = keyed_node();
        // Deliver nonce 2 before nonce 1 — both must still be accepted.
        let n2 = CreditTx::new(alice, bob, 5, 2, 0).sign(&alice_key);
        let n1 = CreditTx::new(alice, bob, 7, 1, 0).sign(&alice_key);
        let mut ledger = CreditLedger::new();
        let report = ledger.reconcile(&[n2, n1]);
        assert_eq!(report.applied, 2);
        assert_eq!(ledger.balance(&bob), 12);
        assert_eq!(ledger.last_nonce(&alice), Some(2));
    }

    #[test]
    fn append_then_reconcile_same_tx_is_a_duplicate() {
        let (alice_key, alice) = keyed_node();
        let (_, bob) = keyed_node();
        let tx = CreditTx::new(alice, bob, 10, 1, 0).sign(&alice_key);
        let mut ledger = CreditLedger::new();
        assert_eq!(ledger.append(tx), Ok(()));
        // The same tx arriving via gossip is recognised as a duplicate.
        let report = ledger.reconcile(&[tx]);
        assert_eq!(report.duplicates, 1);
        assert_eq!(report.applied, 0);
        assert_eq!(ledger.len(), 1);
    }
}

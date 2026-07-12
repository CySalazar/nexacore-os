//! Zero-knowledge predicates for compliance proofs (Phase 4 placeholder).
//!
//! # Status
//!
//! Empty module. The functional implementation lands in Phase 4 once
//! the STARK-vs-SNARK decision is closed via `/ncips/ncip-crypto-002.md`
//! (P3.3 in the backlog).
//!
//! # Decision in flight
//!
//! The roadmap's directional preference is **STARK / transparent
//! constructions** (no trusted setup), with `winterfell` and
//! `triton-vm` as candidate libraries. The final selection will be
//! made by NCIP after benchmarking proof size, prover time, and
//! verifier time on representative compliance predicates (e.g.,
//! "this payload's PII fields satisfy GDPR retention policy P").
//!
//! # When the implementation lands
//!
//! It will provide:
//!
//! * A `ComplianceProof` type carrying the proof bytes plus the
//!   witness-public-input pair.
//! * A `Verifier::verify` method usable by any consumer (mesh peers,
//!   audit logs).
//! * A constrained DSL for expressing the predicate over typed
//!   `EncryptedString` / `MaskedSSN` etc. inputs (so the predicate
//!   author cannot accidentally leak plaintext into the proof).
//!
//! See `/docs/04-security-model.md` § "Compliance proofs".

//! Compile-fail fixture: a `Tier1Request` must NOT be acceptable to the
//! Tier-0-only `BackendRouter` (TASK-08, DE-G1).
//!
//! `BackendRouter::generate` takes `&Tier0Request<GenerateRequest>`.
//! Passing a `Tier1Request<GenerateRequest>` — a deliberately distinct
//! type with no conversion into `Tier0Request` — must be a type error.
//! This pins "the backend router only serves Tier-0 traffic" as a
//! compiler-enforced invariant rather than a convention.

use nexacore_runtime::provider::{BackendPolicy, BackendRouter, GenerateRequest, Tier1Request};

fn main() {
    let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu);
    let tier1 = Tier1Request::new(GenerateRequest {
        model: "m".to_owned(),
        prompt: "p".to_owned(),
        max_tokens: 1,
    });

    // ERROR: expected `&Tier0Request<GenerateRequest>`, found
    // `&Tier1Request<GenerateRequest>`. A Tier-1 request cannot reach the
    // Tier-0-only backend router.
    let _ = router.generate(&tier1);
}

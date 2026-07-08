//! Compile-fail test runner for `nexacore-runtime` typestate invariants —
//! TASK-08 (DE-G1).
//!
//! Each `.rs` file under `tests/compile_fail/` MUST fail to compile for
//! the documented reason — turning a convention ("the backend router is
//! Tier-0-only") into a compiler-enforced guarantee.
//!
//! Run with `cargo test -p nexacore-runtime --test trybuild_compile_fail`.
//! No `.stderr` files are checked in: the test passes as long as the
//! fixture fails to compile *for any reason*, which avoids brittle
//! coupling to compiler-version-specific error messages (same convention
//! as `nexacore-types`).

#[test]
fn compile_fail_invariants() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}

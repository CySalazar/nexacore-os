//! Compile-fail test runner.
//!
//! Each `.rs` file under `tests/compile_fail/` MUST fail to compile
//! for the documented reason. These tests transform "convention" into
//! a compiler-enforced invariant — exactly the kind of guarantee a
//! foundational types crate must offer.
//!
//! Run with `cargo test -p nexacore-types --test trybuild_compile_fail`.
//! No `.stderr` files are checked in: the test passes as long as the
//! fixture fails to compile *for any reason*. This avoids brittle
//! coupling to compiler-version-specific error messages.

#[test]
fn compile_fail_invariants() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}

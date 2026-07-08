//! Generate `docs/15-syscall-abi.md` from the machine-readable ABI source.
//!
//! The frozen syscall ABI reference is no longer maintained by hand: it is
//! rendered from `SYSCALL_ABI_REF` (WS14-01). Regenerate the committed document
//! whenever the source table changes:
//!
//! ```text
//! cargo run -p nexacore-kernel --example gen-syscall-abi > docs/15-syscall-abi.md
//! ```
//!
//! The `generated_doc_matches_committed` test fails until the file is back in
//! sync with the source, so the document can never silently drift.

fn main() {
    print!(
        "{}",
        nexacore_kernel::syscall::abi_reference::render_reference()
    );
}

//! Asserts that the `EncryptedType` trait is sealed: external crates
//! cannot mint new "encrypted" categories.
//!
//! Implementation of `EncryptedType` requires the private super-trait
//! `nexacore_types::encrypted::sealed::Sealed`. That trait is not exported,
//! so any external impl is a compile error.

struct EvilType;

// ERROR: the trait `Sealed` is private; cannot be implemented outside
// the `nexacore-types` crate.
impl nexacore_types::encrypted::EncryptedType for EvilType {
    const KIND: &'static str = "evil";
    fn ciphertext(&self) -> &[u8] {
        &[]
    }
}

fn main() {
    let _ = EvilType;
}

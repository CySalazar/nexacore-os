//! Asserts that there is no public `From<String>` (or `From<&str>`)
//! impl that would let user code mint an `EncryptedString` from
//! cleartext.
//!
//! The fixture deliberately uses `From::from` rather than a method
//! name like `from_str`: the latter would surface a compiler `note:`
//! suggesting the feature-gated `from_ciphertext` constructor when
//! the `_tokenization_provider` feature is enabled, which makes the
//! `.stderr` snapshot vary by configuration. The trait-bound check
//! produces a stable diagnostic in every configuration.

fn main() {
    let plaintext = String::from("very secret PII");
    // ERROR: `EncryptedString` does not implement `From<String>`.
    let _e: nexacore_types::encrypted::EncryptedString = plaintext.into();
}

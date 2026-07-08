//! Asserts that `ModelId` and `NodeId` are NOT interchangeable.
//!
//! If the compiler ever accepted this code, identifier confusion bugs
//! would become possible — exactly what the typed-newtype design exists
//! to prevent.

fn requires_node_id(_n: nexacore_types::NodeId) {}

fn main() {
    let model = nexacore_types::ModelId::from_manifest_hash([0u8; 32]);
    // ERROR: expected `NodeId`, found `ModelId`.
    requires_node_id(model);
}

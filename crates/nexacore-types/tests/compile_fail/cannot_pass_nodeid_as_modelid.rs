//! Asserts the reverse direction of `cannot_pass_modelid_as_nodeid`:
//! a `NodeId` cannot be passed where a `ModelId` is expected.

fn requires_model_id(_m: nexacore_types::ModelId) {}

fn main() {
    let node = nexacore_types::NodeId::from_attestation_hash([0u8; 32]);
    // ERROR: expected `ModelId`, found `NodeId`.
    requires_model_id(node);
}

use axiom_eth::rlc::circuit::RlcCircuitParams;

/// Computes results root (keccak), results root (poseidon), and subquery hashes by making promise calls to subquery circuits.
pub mod results;
/// The subquery circuits
pub mod subqueries;

pub const MAX_MERKLE_TREE_HEIGHT_FOR_KECCAK_RESULTS: usize = 3;
/// Helper function for testing to create a dummy RlcCircuitParams
pub fn dummy_rlc_circuit_params(k: usize) -> RlcCircuitParams {
    let mut circuit_params = RlcCircuitParams::default();
    circuit_params.base.k = k;
    circuit_params.base.lookup_bits = Some(8);
    circuit_params.base.num_instance_columns = 1;
    circuit_params.num_rlc_columns = 1;
    circuit_params
}

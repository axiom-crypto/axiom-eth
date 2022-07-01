use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, CircuitExt};

use crate::utils::snark_verifier::AggregationCircuitParams;

pub trait CircuitMetadata {
    const HAS_ACCUMULATOR: bool;

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        if Self::HAS_ACCUMULATOR {
            AggregationCircuit::accumulator_indices()
        } else {
            None
        }
    }
    fn num_instance(&self) -> Vec<usize>;
}

pub fn get_dummy_aggregation_params(k: usize) -> AggregationCircuitParams {
    AggregationCircuitParams { degree: k as u32, lookup_bits: k - 1, ..Default::default() }
}

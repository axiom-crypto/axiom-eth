use axiom_eth::{
    halo2_base::utils::halo2::KeygenCircuitIntent,
    halo2_proofs::{
        plonk::Circuit,
        poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    },
    halo2curves::bn256::Bn256,
    rlc::virtual_region::RlcThreadBreakPoints,
    utils::{
        component::circuit::{CoreBuilderOutputParams, CoreBuilderParams},
        keccak::get_keccak_unusable_rows_from_capacity,
    },
    zkevm_hashes::{
        keccak::component::circuit::shard::{
            KeccakComponentShardCircuit, KeccakComponentShardCircuitParams,
        },
        util::eth_types::Field as RawField,
    },
};
use serde::{Deserialize, Serialize};

use super::{ComponentShardPinning, Fr};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ShardIntentKeccak {
    pub core_params: CoreParamsKeccak,
    pub k: u32,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CoreParamsKeccak {
    pub capacity: usize,
}

// Not sure this is needed
impl CoreBuilderParams for CoreParamsKeccak {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        CoreBuilderOutputParams::new(vec![self.capacity])
    }
}

impl KeygenCircuitIntent<Fr> for ShardIntentKeccak {
    type ConcreteCircuit = KeccakComponentShardCircuit<Fr>;
    type Pinning = ComponentShardPinning<Self::ConcreteCircuit>;

    fn get_k(&self) -> u32 {
        self.k
    }
    fn build_keygen_circuit(self) -> Self::ConcreteCircuit {
        let circuit_params = KeccakComponentShardCircuitParams::new(
            self.k as usize,
            0, // unusable_rows will be recalculated later in tuning
            self.core_params.capacity,
            false,
        );
        let mut circuit = KeccakComponentShardCircuit::new(vec![], circuit_params, false);
        tune_keccak_component_shard_circuit(&mut circuit);
        circuit
    }
    fn get_pinning_after_keygen(
        self,
        kzg_params: &ParamsKZG<Bn256>,
        circuit: &Self::ConcreteCircuit,
    ) -> Self::Pinning {
        let break_points = circuit.base_circuit_break_points();
        assert_eq!(break_points.len(), 1);
        let svk = kzg_params.get_g()[0];
        let dk = (svk, kzg_params.g2(), kzg_params.s_g2());
        ComponentShardPinning {
            params: circuit.params(),
            num_instance: vec![1], // keccak component shard only has 1 instance
            break_points: RlcThreadBreakPoints { base: break_points, rlc: vec![] },
            dk: dk.into(),
        }
    }
}

/// Finds and sets optimal configuration parameters for [KeccakComponentShardCircuit].
pub fn tune_keccak_component_shard_circuit<F: RawField>(
    circuit: &mut KeccakComponentShardCircuit<F>,
) {
    let circuit_params = circuit.params();
    let k = circuit_params.k();
    let capacity = circuit_params.capacity();
    let (unusable, _) = get_keccak_unusable_rows_from_capacity(k, capacity);
    let mut circuit_params = KeccakComponentShardCircuitParams::new(
        k,
        unusable,
        capacity,
        circuit_params.publish_raw_outputs(),
    );
    circuit_params.base_circuit_params =
        KeccakComponentShardCircuit::<F>::calculate_base_circuit_params(&circuit_params);
    *circuit.params_mut() = circuit_params;
}

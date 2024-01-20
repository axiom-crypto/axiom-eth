use anyhow::{bail, Result};
use axiom_codec::utils::native::encode_addr_to_field;
use axiom_eth::{
    halo2_base::gates::circuit::CircuitBuilderStage,
    halo2_proofs::poly::kzg::commitment::ParamsKZG,
    halo2curves::bn256::Bn256,
    snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, SHPLONK},
    utils::{
        build_utils::pinning::aggregation::AggregationCircuitPinning,
        snark_verifier::{
            create_universal_aggregation_circuit, AggregationCircuitParams, EnhancedSnark,
            NUM_FE_ACCUMULATOR,
        },
    },
};
use ethers_core::types::Address;
use serde::{Deserialize, Serialize};

use crate::axiom_aggregation1::types::{
    LogicalPublicInstanceAxiomAggregation, FINAL_AGG_VKEY_HASH_IDX,
};

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputAxiomAggregation2 {
    pub payee: Address,
    /// Snark from AxiomAggregation1
    pub snark_axiom_agg1: EnhancedSnark,
}

impl InputAxiomAggregation2 {
    pub fn build(
        self,
        stage: CircuitBuilderStage,
        circuit_params: AggregationCircuitParams,
        kzg_params: &ParamsKZG<Bn256>,
    ) -> anyhow::Result<AggregationCircuit> {
        if self.snark_axiom_agg1.agg_vk_hash_idx != Some(FINAL_AGG_VKEY_HASH_IDX) {
            bail!("AxiomAggregation1 snark agg_vkey_hash_idx exception");
        }
        let (mut circuit, mut previous_instances, agg_vkey_hash) =
            create_universal_aggregation_circuit::<SHPLONK>(
                stage,
                circuit_params,
                kzg_params,
                vec![self.snark_axiom_agg1.inner],
                vec![Some(FINAL_AGG_VKEY_HASH_IDX)],
            );
        let instances = previous_instances.pop().unwrap();
        let prev_pis = LogicalPublicInstanceAxiomAggregation::try_from(instances)?;

        let builder = &mut circuit.builder;
        let payee = builder.main(0).load_witness(encode_addr_to_field(&self.payee));

        let logical_pis = LogicalPublicInstanceAxiomAggregation {
            agg_vkey_hash,      // use new agg_vkey_hash
            payee: Some(payee), // previously there was no payee
            ..prev_pis          // re-expose previous public instances
        };

        if builder.assigned_instances.len() != 1 {
            bail!("should only have 1 instance column");
        }
        assert_eq!(builder.assigned_instances[0].len(), NUM_FE_ACCUMULATOR);
        builder.assigned_instances[0].extend(logical_pis.flatten());

        Ok(circuit)
    }

    /// Circuit for witness generation only
    pub fn prover_circuit(
        self,
        pinning: AggregationCircuitPinning,
        kzg_params: &ParamsKZG<Bn256>,
    ) -> Result<AggregationCircuit> {
        Ok(self
            .build(CircuitBuilderStage::Prover, pinning.params, kzg_params)?
            .use_break_points(pinning.break_points))
    }
}

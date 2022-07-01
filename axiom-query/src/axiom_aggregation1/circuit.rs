use anyhow::{bail, Result};
use axiom_eth::{
    halo2_base::gates::{circuit::CircuitBuilderStage, GateChip},
    halo2_proofs::poly::kzg::commitment::ParamsKZG,
    halo2curves::bn256::Bn256,
    snark_verifier_sdk::{
        halo2::{aggregation::AggregationCircuit, POSEIDON_SPEC},
        SHPLONK,
    },
    utils::{
        build_utils::pinning::aggregation::AggregationCircuitPinning,
        component::types::{ComponentPublicInstances, PoseidonHasher},
        snark_verifier::{
            create_universal_aggregation_circuit, AggregationCircuitParams, NUM_FE_ACCUMULATOR,
        },
    },
};

use crate::{
    axiom_aggregation1::types::LogicalPublicInstanceAxiomAggregation,
    subquery_aggregation::types::{
        LogicalPublicInstanceSubqueryAgg, SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX,
    },
    verify_compute::types::LogicalPisVerifyComputeWithoutAccumulator,
};

use super::types::InputAxiomAggregation1;

impl InputAxiomAggregation1 {
    /// Builds general circuit
    ///
    /// Warning: this MUST return a circuit implementing `CircuitExt` with accumulator indices provided.
    /// In particular, do not return `BaseCircuitBuilder`.
    pub fn build(
        self,
        stage: CircuitBuilderStage,
        circuit_params: AggregationCircuitParams,
        kzg_params: &ParamsKZG<Bn256>,
    ) -> Result<AggregationCircuit> {
        let agg_vkey_hash_indices = vec![None, Some(SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX), None];
        let snarks = [self.snark_verify_compute, self.snark_subquery_agg, self.snark_keccak_agg];
        for (i, snark) in snarks.iter().enumerate() {
            if snark.agg_vk_hash_idx != agg_vkey_hash_indices[i] {
                bail!("[AxiomAggregation1] agg_vkey_hash_idx mismatch in snark {i}");
            }
        }
        let (mut circuit, previous_instances, agg_vkey_hash) =
            create_universal_aggregation_circuit::<SHPLONK>(
                stage,
                circuit_params,
                kzg_params,
                snarks.map(|s| s.inner).to_vec(),
                agg_vkey_hash_indices,
            );

        let builder = &mut circuit.builder;
        let ctx = builder.main(0);

        let [pis_verify_compute, instances_subquery_agg, mut instances_keccak]: [_; 3] =
            previous_instances.try_into().unwrap();
        let pis_verify_compute = ComponentPublicInstances::try_from(pis_verify_compute)?;

        let LogicalPisVerifyComputeWithoutAccumulator {
            source_chain_id,
            compute_results_hash,
            query_hash,
            query_schema,
            results_root_poseidon: promise_results_root_poseidon,
            promise_subquery_hashes,
        } = pis_verify_compute.other.try_into()?;

        let LogicalPublicInstanceSubqueryAgg {
            promise_keccak,
            agg_vkey_hash: _, // already read in create_universal_aggregation_circuit
            results_root_poseidon,
            commit_subquery_hashes,
            mmr_keccak,
        } = instances_subquery_agg.try_into()?;

        log::debug!("promise_results_root_poseidon: {:?}", promise_results_root_poseidon.value());
        log::debug!("results_root_poseidon: {:?}", results_root_poseidon.value());
        log::debug!("promise_subquery_hashes: {:?}", promise_subquery_hashes.value());
        log::debug!("commit_subquery_hashes: {:?}", commit_subquery_hashes.value());
        ctx.constrain_equal(&promise_results_root_poseidon, &results_root_poseidon);
        ctx.constrain_equal(&promise_subquery_hashes, &commit_subquery_hashes);

        let commit_keccak = instances_keccak.pop().unwrap();
        // Await keccak promises:
        // * The promise_keccak from SubqueryAggregation should directly equal the output commit of keccak component
        // * The promise_result_commit from VerifyCompute should equal poseidon_hash([commit_keccak])
        log::debug!(
            "subquery_agg promise_keccak: {:?} commit_keccak: {:?}",
            promise_keccak.value(),
            commit_keccak.value()
        );
        ctx.constrain_equal(&promise_keccak, &commit_keccak);
        // ======== Create Poseidon hasher ===========
        let gate = GateChip::default();
        let mut hasher = PoseidonHasher::new(POSEIDON_SPEC.clone());
        hasher.initialize_consts(ctx, &gate);
        let hashed_commit_keccak = hasher.hash_fix_len_array(ctx, &gate, &[commit_keccak]);
        log::debug!("hash(commit_keccak): {:?}", hashed_commit_keccak.value());
        log::debug!(
            "verify_compute promise_commit: {:?}",
            pis_verify_compute.promise_result_commit.value()
        );
        ctx.constrain_equal(&pis_verify_compute.promise_result_commit, &hashed_commit_keccak);

        let logical_pis = LogicalPublicInstanceAxiomAggregation {
            source_chain_id,
            compute_results_hash,
            query_hash,
            query_schema,
            blockhash_mmr_keccak: mmr_keccak,
            agg_vkey_hash,
            payee: None,
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

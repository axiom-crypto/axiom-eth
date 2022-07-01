use std::iter;

use anyhow::bail;
use axiom_codec::{types::field_elements::FlattenedSubqueryResult, HiLo};
use axiom_eth::{
    halo2_base::AssignedValue,
    halo2curves::bn256::{Fr, G1Affine},
    impl_flatten_conversion,
    snark_verifier_sdk::{halo2::gen_dummy_snark_from_protocol, Snark, SHPLONK},
    utils::{
        build_utils::dummy::DummyFrom,
        component::{
            circuit::{CoreBuilderOutputParams, CoreBuilderParams},
            types::LogicalEmpty,
            ComponentType, ComponentTypeId, LogicalResult,
        },
        snark_verifier::NUM_FE_ACCUMULATOR,
    },
};
use getset::{CopyGetters, Getters};
use serde::{Deserialize, Serialize};

use crate::{
    components::results::{table::SubqueryResultsTable, types::CircuitOutputResultsRoot},
    utils::client_circuit::{metadata::AxiomV2CircuitMetadata, vkey::OnchainVerifyingKey},
};

/// Identifier for the component type of Verify Compute Circuit
pub struct ComponentTypeVerifyCompute;

/// Configuration parameters for Verify Compute Circuit that determine
/// the circuit, **independent** of the variable inputs.
///
/// Even when `nonempty_compute_query == false` (no compute query),
/// the `circuit_params.client_metadata` needs to be set to a valid
/// client circuit configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Getters, CopyGetters)]
pub struct CoreParamsVerifyCompute {
    /// Capacity: max number of subquery results
    #[getset(get_copy = "pub")]
    subquery_results_capacity: usize,
    /// Succinct verifying key should be the generator `g()[0]` of the KZG trusted setup used to generate the vkey.
    #[getset(get_copy = "pub")]
    svk: G1Affine, // Svk type doesn't derive Serialize
    /// Client circuit on-chain vkey
    #[getset(get = "pub")]
    client_metadata: AxiomV2CircuitMetadata,
    /// Length of `preprocessed` in `PlonkProtocol`
    #[getset(get_copy = "pub")]
    preprocessed_len: usize,
}

impl CoreParamsVerifyCompute {
    pub fn new(
        subquery_results_capacity: usize,
        svk: G1Affine,
        client_metadata: AxiomV2CircuitMetadata,
        preprocessed_len: usize,
    ) -> Self {
        Self { subquery_results_capacity, svk, client_metadata, preprocessed_len }
    }
}
impl CoreBuilderParams for CoreParamsVerifyCompute {
    /// No component output
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        CoreBuilderOutputParams::new(vec![])
    }
}

/// Logic inputs to Verify Compute Circuit
/// Deserialization is specialized to [Fr] for now.
///
/// ## Compute Snark
/// The Verify Compute Circuit should only depend on the number of columns and custom gates / lookup arguments
/// of `compute_snark`, not on the fixed commitments or domain size `2^k`.
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct CircuitInputVerifyCompute {
    /// Chain ID of the chain the EVM data is from
    pub source_chain_id: u64,
    /// Used for lookups, length may be padded with dummy subqueries
    pub subquery_results: CircuitOutputResultsRoot<Fr>,
    /// If `nonempty_compute_query == false`, then `compute_snark` is a dummy snark.
    pub nonempty_compute_query: bool,
    /// The number of user results
    pub result_len: u16,
    /// The client snark.
    ///
    /// When there is no compute query (`nonempty_compute_query == false`),
    /// this must be a dummy snark matching `circuit_params.client_metadata` that will still verify.
    #[getset(get = "pub")]
    pub(super) compute_snark: Snark,
}

impl CircuitInputVerifyCompute {
    /// If `nonempty_compute_query == false`, then `compute_snark` must be a dummy snark that will verify.
    pub fn new(
        source_chain_id: u64,
        subquery_results: CircuitOutputResultsRoot<Fr>,
        nonempty_compute_query: bool,
        result_len: u16,
        compute_snark: Snark,
    ) -> Self {
        Self {
            source_chain_id,
            subquery_results,
            nonempty_compute_query,
            result_len,
            compute_snark,
        }
    }
}

impl DummyFrom<CoreParamsVerifyCompute> for CircuitInputVerifyCompute {
    fn dummy_from(core_params: CoreParamsVerifyCompute) -> Self {
        let subquery_results_capacity = core_params.subquery_results_capacity();
        let onchain_vk = OnchainVerifyingKey {
            circuit_metadata: core_params.client_metadata().clone(),
            transcript_initial_state: Default::default(),
            preprocessed: vec![G1Affine::default(); core_params.preprocessed_len()],
        };
        // k is loaded as witness so it shouldn't matter
        let k = 7;
        let protocol = onchain_vk.into_plonk_protocol(k).unwrap();
        let compute_snark = gen_dummy_snark_from_protocol::<SHPLONK>(protocol);
        let results = SubqueryResultsTable {
            rows: vec![FlattenedSubqueryResult::default(); subquery_results_capacity],
        };
        let subquery_hashes = vec![HiLo::default(); subquery_results_capacity];

        let subquery_results =
            CircuitOutputResultsRoot { results, subquery_hashes, num_subqueries: 0 };
        Self::new(0, subquery_results, true, 0, compute_snark)
    }
}

pub(super) const NUM_LOGICAL_INSTANCE_WITHOUT_ACC: usize = 1 + 2 + 2 + 2 + 1 + 1;
pub(super) const NUM_LOGICAL_INSTANCE: usize =
    NUM_FE_ACCUMULATOR + NUM_LOGICAL_INSTANCE_WITHOUT_ACC;
const NUM_BITS_PER_FE: [usize; NUM_LOGICAL_INSTANCE] = get_num_bits_per_fe();
// 9999 means that the public instance takes a whole witness
// Accumulators *must* take whole witnesses.
const fn get_num_bits_per_fe() -> [usize; NUM_LOGICAL_INSTANCE] {
    let mut bits_per = [9999; NUM_LOGICAL_INSTANCE];
    bits_per[NUM_FE_ACCUMULATOR] = 64;
    bits_per[NUM_FE_ACCUMULATOR + 1] = 128;
    bits_per[NUM_FE_ACCUMULATOR + 2] = 128;
    bits_per[NUM_FE_ACCUMULATOR + 3] = 128;
    bits_per[NUM_FE_ACCUMULATOR + 4] = 128;
    bits_per[NUM_FE_ACCUMULATOR + 5] = 128;
    bits_per[NUM_FE_ACCUMULATOR + 6] = 128;
    bits_per
}
/// The public instances of the circuit, **excluding** the component owned instances
/// for output commit and promise commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalPublicInstanceVerifyCompute<T> {
    pub accumulator: Vec<T>,
    pub source_chain_id: T,
    pub compute_results_hash: HiLo<T>,
    pub query_hash: HiLo<T>,
    pub query_schema: HiLo<T>,
    pub results_root_poseidon: T,
    pub promise_subquery_hashes: T,
}
/// [LogicalPublicInstanceVerifyCompute] with `accumulator` removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalPisVerifyComputeWithoutAccumulator<T> {
    pub source_chain_id: T,
    pub compute_results_hash: HiLo<T>,
    pub query_hash: HiLo<T>,
    pub query_schema: HiLo<T>,
    pub results_root_poseidon: T,
    pub promise_subquery_hashes: T,
}

type F = Fr;
/// Verify Compute has no virtual table as output
impl ComponentType<F> for ComponentTypeVerifyCompute {
    type InputValue = LogicalEmpty<F>;
    type InputWitness = LogicalEmpty<AssignedValue<F>>;
    type OutputValue = LogicalEmpty<F>;
    type OutputWitness = LogicalEmpty<AssignedValue<F>>;
    type LogicalInput = LogicalEmpty<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-query:ComponentTypeVerifyCompute".to_string()
    }
    fn logical_result_to_virtual_rows_impl(
        _ins: &LogicalResult<F, Self>,
    ) -> Vec<(Self::InputValue, Self::OutputValue)> {
        unreachable!()
    }
    fn logical_input_to_virtual_rows_impl(_li: &Self::LogicalInput) -> Vec<Self::InputValue> {
        unreachable!()
    }
}

// ============== LogicalPublicInstanceVerifyCompute ==============
impl<T: Copy> LogicalPublicInstanceVerifyCompute<T> {
    pub fn flatten(self) -> Vec<T> {
        iter::empty()
            .chain(self.accumulator)
            .chain(Some(self.source_chain_id))
            .chain(self.compute_results_hash.hi_lo())
            .chain(self.query_hash.hi_lo())
            .chain(self.query_schema.hi_lo())
            .chain([self.results_root_poseidon, self.promise_subquery_hashes])
            .collect()
    }
}

impl<T: Copy> TryFrom<Vec<T>> for LogicalPublicInstanceVerifyCompute<T> {
    type Error = anyhow::Error;

    fn try_from(mut value: Vec<T>) -> anyhow::Result<Self> {
        if value.len() != NUM_LOGICAL_INSTANCE {
            bail!("wrong number of logical public instances")
        };
        let accumulator = value.drain(..NUM_FE_ACCUMULATOR).collect();
        let drained: LogicalPisVerifyComputeWithoutAccumulator<T> = value.try_into().unwrap();
        Ok(Self {
            accumulator,
            source_chain_id: drained.source_chain_id,
            compute_results_hash: drained.compute_results_hash,
            query_hash: drained.query_hash,
            query_schema: drained.query_schema,
            results_root_poseidon: drained.results_root_poseidon,
            promise_subquery_hashes: drained.promise_subquery_hashes,
        })
    }
}
impl<T: Copy> TryFrom<Vec<T>> for LogicalPisVerifyComputeWithoutAccumulator<T> {
    type Error = anyhow::Error;

    fn try_from(value: Vec<T>) -> anyhow::Result<Self> {
        if value.len() != NUM_LOGICAL_INSTANCE_WITHOUT_ACC {
            bail!("wrong number of logical public instances without accumulator")
        };
        let source_chain_id = value[0];
        let compute_results_hash = HiLo::from_hi_lo([value[1], value[2]]);
        let query_hash = HiLo::from_hi_lo([value[3], value[4]]);
        let query_schema = HiLo::from_hi_lo([value[5], value[6]]);
        let results_root_poseidon = value[7];
        let promise_subquery_hashes = value[8];
        Ok(Self {
            source_chain_id,
            compute_results_hash,
            query_hash,
            query_schema,
            results_root_poseidon,
            promise_subquery_hashes,
        })
    }
}

impl_flatten_conversion!(LogicalPublicInstanceVerifyCompute, NUM_BITS_PER_FE);

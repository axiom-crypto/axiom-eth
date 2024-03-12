use std::iter::zip;

use anyhow::bail;
use axiom_codec::{
    constants::{MAX_SUBQUERY_OUTPUTS, USER_RESULT_FIELD_ELEMENTS, USER_RESULT_LEN_BYTES},
    types::field_elements::SUBQUERY_RESULT_LEN,
    HiLo,
};
use axiom_eth::{
    halo2_base::{
        gates::{GateInstructions, RangeInstructions},
        halo2_proofs::halo2curves::bn256::Fr,
        safe_types::{SafeBytes32, SafeTypeChip},
        AssignedValue,
        QuantumCell::Constant,
    },
    halo2_proofs::plonk::ConstraintSystem,
    keccak::{types::ComponentTypeKeccak, KeccakChip},
    rlc::{
        circuit::builder::RlcCircuitBuilder,
        types::{AssignedVarLenVec, ConcatVarFixedArrayWitness},
    },
    snark_verifier_sdk::{
        halo2::aggregation::{
            aggregate_snarks, AggregationCircuit, PreprocessedAndDomainAsWitness,
            SnarkAggregationOutput, VerifierUniversality,
        },
        CircuitExt, SHPLONK,
    },
    utils::{
        build_utils::aggregation::CircuitMetadata,
        circuit_utils::unsafe_lt_mask,
        component::{
            circuit::{ComponentBuilder, ComponentCircuitImpl, CoreBuilder, CoreBuilderOutput},
            promise_collector::PromiseCaller,
            promise_loader::single::PromiseLoader,
            types::FixLenLogical,
            utils::create_hasher,
            NUM_COMPONENT_OWNED_INSTANCES,
        },
        enforce_conditional_equality,
        snark_verifier::NUM_FE_ACCUMULATOR,
        uint_to_bytes_be,
    },
};
use itertools::{zip_eq, EitherOrBoth, Itertools};

use crate::{
    components::results::results_root::get_results_root_poseidon, ff::Field as _,
    utils::client_circuit::vkey::OnchainVerifyingKey,
    verify_compute::types::LogicalPublicInstanceVerifyCompute,
};

use super::{
    query_hash::{
        encode_compute_query_phase1, encode_query_schema, get_data_query_hash, get_query_hash_v2,
        get_query_schema_hash,
    },
    types::{CircuitInputVerifyCompute, ComponentTypeVerifyCompute, CoreParamsVerifyCompute},
};

type F = Fr; // Specialize to Fr for aggregation

pub struct CoreBuilderVerifyCompute {
    input: Option<CircuitInputVerifyCompute>,
    params: CoreParamsVerifyCompute,
    payload: Option<(KeccakChip<F>, ConcatVarFixedArrayWitness<F>)>,
}

pub type PromiseLoaderVerifyCompute = PromiseLoader<F, ComponentTypeKeccak<F>>;
pub type ComponentCircuitVerifyCompute =
    ComponentCircuitImpl<F, CoreBuilderVerifyCompute, PromiseLoaderVerifyCompute>;

impl CircuitMetadata for CoreBuilderVerifyCompute {
    const HAS_ACCUMULATOR: bool = true;
    /// IMPORTANT: Unlike most aggregation circuits, the accumulator indices here DO NOT start from 0 because the first [NUM_COMPONENT_OWNED_INSTANCES] are owned by [`ComponentCircuitImpl`].
    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        Some((0..NUM_FE_ACCUMULATOR).map(|i| (0, NUM_COMPONENT_OWNED_INSTANCES + i)).collect())
    }
    fn num_instance(&self) -> Vec<usize> {
        // For reference only, overridden by `num_instance` in `ComponentCircuitImpl`
        vec![
            NUM_COMPONENT_OWNED_INSTANCES + NUM_FE_ACCUMULATOR + super::types::NUM_LOGICAL_INSTANCE,
        ]
    }
}

impl CoreBuilderVerifyCompute {
    pub fn client_max_outputs(&self) -> usize {
        self.params.client_metadata().max_outputs as usize
    }
}

impl ComponentBuilder<F> for CoreBuilderVerifyCompute {
    type Params = CoreParamsVerifyCompute;

    fn new(params: Self::Params) -> Self {
        Self { input: None, params, payload: None }
    }
    fn get_params(&self) -> Self::Params {
        self.params.clone()
    }
    fn clear_witnesses(&mut self) {
        self.payload = None;
    }
    fn calculate_params(&mut self) -> Self::Params {
        self.params.clone()
    }
    fn configure_with_params(_: &mut ConstraintSystem<F>, _: Self::Params) {}
}

impl CoreBuilder<F> for CoreBuilderVerifyCompute {
    type CompType = ComponentTypeVerifyCompute;
    type PublicInstanceValue = LogicalPublicInstanceVerifyCompute<F>;
    type PublicInstanceWitness = LogicalPublicInstanceVerifyCompute<AssignedValue<F>>;
    type CoreInput = CircuitInputVerifyCompute;

    /// Checks that the circuit params (fixed in circuit) match the parts of the inputs that are witnesses (variable in circuit).
    ///
    /// If `nonempty_compute_query == false`, then `compute_snark` must be a dummy snark that will verify.
    fn feed_input(&mut self, mut input: Self::CoreInput) -> anyhow::Result<()> {
        let cap = self.params.subquery_results_capacity();
        let len = input.subquery_results.results.len();
        if cap < len {
            bail!("Feed CircuitInputVerifyCompute Error: length of subquery_results {len} is greater than subquery_results_capacity {cap}");
        }
        input.subquery_results.resize_with_first(cap);
        if self.params.preprocessed_len() != input.compute_snark().protocol.preprocessed.len() {
            bail!("Feed CircuitInputVerifyCompute Error: preprocessed_len does not match compute_snark");
        }
        // Enforce that the PlonkProtocol in compute_snark **must** be consistent with circuit_params.circuit_metadata
        // circuit_metadata is fixed, but transcript_initial_state and preprocessed may be variable
        let compute_snark = &mut input.compute_snark;
        let client_vk = OnchainVerifyingKey {
            circuit_metadata: self.params.client_metadata().clone(),
            transcript_initial_state: compute_snark.protocol.transcript_initial_state.unwrap(),
            preprocessed: std::mem::take(&mut compute_snark.protocol.preprocessed),
        };
        compute_snark.protocol = client_vk.into_plonk_protocol(compute_snark.protocol.domain.k)?;

        self.input = Some(input);
        Ok(())
    }

    fn virtual_assign_phase0(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_caller: PromiseCaller<F>,
    ) -> CoreBuilderOutput<F, Self::CompType> {
        // preamble
        let keccak_chip =
            KeccakChip::new_with_promise_collector(builder.range_chip(), promise_caller.clone());
        let keccak = &keccak_chip;
        let range = keccak.range();
        let gate = range.gate();
        let safe = SafeTypeChip::new(range);

        // Assumption: we already have input when calling this function.
        let input = self.input.as_ref().unwrap();
        // verify compute
        let pool = builder.base.pool(0);
        let SnarkAggregationOutput {
            mut preprocessed,
            mut previous_instances,
            accumulator,
            mut proof_transcripts,
        } = aggregate_snarks::<SHPLONK>(
            pool,
            range,
            self.params.svk().into(),
            [input.compute_snark().clone()],
            VerifierUniversality::Full,
        );
        let ctx = builder.base.main(0);
        let source_chain_id = ctx.load_witness(F::from(input.source_chain_id));
        let ne_cq = safe.load_bool(ctx, input.nonempty_compute_query);
        // get information from the compute snark
        let PreprocessedAndDomainAsWitness { mut preprocessed, k } = preprocessed.pop().unwrap();
        let transcript_init_state = preprocessed.pop().unwrap();
        let compute_proof_transcript = proof_transcripts.pop().unwrap();
        let mut compute_instances = previous_instances.pop().unwrap();
        // check if `compute_snark` was an aggregation circuit. if it is, remove the old accumulator from the compute_snark public instances
        let compute_accumulator = {
            let acc_indices = &input.compute_snark().protocol.accumulator_indices;
            if acc_indices.is_empty() {
                None
            } else {
                assert_eq!(acc_indices.len(), 1);
                // For uniformity, we only allow aggregation circuit accumulator indices to be (0,0), ..., (0, 4 * LIMBS - 1)
                assert_eq!(&acc_indices[0], &AggregationCircuit::accumulator_indices().unwrap());
                Some(compute_instances.drain(0..NUM_FE_ACCUMULATOR).collect_vec())
            }
        };
        let mut compute_results = compute_instances;
        let query_instances =
            compute_results.split_off(USER_RESULT_FIELD_ELEMENTS * self.client_max_outputs());
        let result_len = ctx.load_witness(F::from(input.result_len as u64));
        const RESULT_LEN_BITS: usize = 8 * USER_RESULT_LEN_BYTES;
        range.range_check(ctx, result_len, RESULT_LEN_BITS);
        // Note: result_len is the length in number of HiLos, so `compute_results` should be thought of as having variable length `2 * result_len`
        let compute_results = AssignedVarLenVec { values: compute_results, len: result_len };
        // get query schema
        let encoded_query_schema = encode_query_schema(
            ctx,
            range,
            k,
            result_len,
            self.params.client_metadata(),
            transcript_init_state,
            &preprocessed,
        );
        let query_schema = get_query_schema_hash(ctx, keccak, &encoded_query_schema, ne_cq);
        // load subquery hashes
        let subquery_hashes = &input.subquery_results.subquery_hashes;
        let (subquery_hashes, subquery_hashes_hilo): (Vec<_>, Vec<_>) = subquery_hashes
            .iter()
            .map(|subquery_hash| {
                let hilo = subquery_hash.hi_lo();
                let hilo = hilo.map(|x| ctx.load_witness(x));
                let bytes = hilo.map(|x| uint_to_bytes_be(ctx, range, &x, 16)).concat();
                (SafeBytes32::try_from(bytes).unwrap(), hilo)
            })
            .unzip();
        // get data query hash
        let num_subqueries = input.subquery_results.num_subqueries as u64;
        let num_subqueries = ctx.load_witness(F::from(num_subqueries));
        let total_subquery_capacity = input.subquery_results.results.len() as u64;
        range.check_less_than_safe(ctx, num_subqueries, total_subquery_capacity + 1);
        let (data_query_hash, encoded_source_chain_id) =
            get_data_query_hash(ctx, keccak, source_chain_id, &subquery_hashes, num_subqueries);
        // get query hash
        let (query_hash, concat_proof_witness) = get_query_hash_v2(
            ctx,
            keccak,
            &encoded_source_chain_id,
            &data_query_hash,
            &encoded_query_schema,
            compute_accumulator,
            &compute_results,
            compute_proof_transcript,
            ne_cq,
        );

        // result_len should be <= user.max_outputs if computeQuery non-empty, otherwise <= num_subqueries
        let max_res_len = gate.select(
            ctx,
            Constant(F::from(self.client_max_outputs() as u64)),
            num_subqueries,
            ne_cq,
        );
        let max_res_len_p1 = gate.inc(ctx, max_res_len);
        range.check_less_than(ctx, result_len, max_res_len_p1, RESULT_LEN_BITS);
        // Load subquery results from custom promise call
        let table = input.subquery_results.results.assign(ctx);
        // If user query nonempty, then table must match `query_instances`
        assert_eq!(query_instances.len() % SUBQUERY_RESULT_LEN, 0);
        let user_subqueries = query_instances.chunks_exact(SUBQUERY_RESULT_LEN);
        // we will force user subquery to be 0 for index >= num_subqueries. Due to re-sizing logic in ResultsRoot circuit, the table.rows might not be 0 for those indices.
        let subquery_mask =
            unsafe_lt_mask(ctx, gate, num_subqueries, total_subquery_capacity as usize);
        for (i, it) in user_subqueries.zip_longest(&table.rows).enumerate() {
            match it {
                EitherOrBoth::Both(user, row) => {
                    let key = &row.key.0;
                    let out = &row.value.0;
                    for (&usr, &res) in zip(user, key.iter().chain(out.iter())) {
                        let res = gate.mul(ctx, res, subquery_mask[i]);
                        enforce_conditional_equality(ctx, gate, usr, res, ne_cq);
                    }
                }
                EitherOrBoth::Left(user) => {
                    // If for some reason we allow promise table to be shorter than user max subqueries, the extra user subqueries should all be Null
                    for v in user {
                        gate.assert_is_const(ctx, v, &Fr::ZERO);
                    }
                }
                EitherOrBoth::Right(_) => {
                    // It is OK to have more promised subquery results than user subqueries
                    break;
                }
            }
        }

        // user results are bytes32 in hi-lo form, we need to compute keccak hash of the bytes32 concatenated
        // length in bytes
        let result_byte_len = gate.mul(ctx, result_len, Constant(F::from(32)));
        // The compute results are the `compute_results` if non-empty computeQuery. Otherwise they are the first `result_len` output values from the subquery results table
        // We account for the fact that `compute_results` and `table.rows` can have different compile-time lengths
        let mut compute_results_bytes = vec![];
        for it in
            compute_results.values.chunks_exact(USER_RESULT_FIELD_ELEMENTS).zip_longest(&table.rows)
        {
            // hi-lo form
            let words = match it {
                EitherOrBoth::Both(user, subquery_res) => zip_eq(user, &subquery_res.value.0)
                    .map(|(&user, &val)| gate.select(ctx, user, val, *ne_cq.as_ref()))
                    .collect_vec(),
                EitherOrBoth::Left(user) => user.to_vec(),
                EitherOrBoth::Right(subquery_res) => subquery_res.value.0.to_vec(),
            };
            for word in &words {
                // this performs the 128 bit range check:
                compute_results_bytes.extend(uint_to_bytes_be(ctx, range, word, 16));
            }
        }
        // we checked result_len <= computeQuery.k != 0 ? user.max_outputs : num_subqueries above
        // so the above selection is safe
        let compute_results_hash = keccak.keccak_var_len(
            ctx,
            compute_results_bytes.into_iter().map(From::from).collect(),
            result_byte_len,
            0,
        );

        // not optimal: recomputing spec even though PromiseLoader also uses hasher
        let mut poseidon = create_hasher();
        poseidon.initialize_consts(ctx, range.gate());
        // generate promise commit from table and subquery_hashes
        let results_root_poseidon = {
            assert_eq!(table.rows.len(), total_subquery_capacity as usize);
            get_results_root_poseidon(
                ctx,
                range,
                &poseidon,
                &table.rows,
                num_subqueries,
                &subquery_mask,
            )
        };
        let promise_subquery_hashes = {
            // this exactly matches what is done in resultsRoot component circuit.
            // however `max_num_subqueries` here does not need to match the `total_subquery_capacity` in ResultsRoot circuit
            let to_commit = subquery_hashes_hilo.into_iter().flatten().collect_vec();
            let len = gate.mul(ctx, num_subqueries, Constant(F::from(MAX_SUBQUERY_OUTPUTS as u64)));
            poseidon.hash_var_len_array(ctx, range, &to_commit, len)
        };

        let logical_pis = LogicalPublicInstanceVerifyCompute {
            accumulator,
            source_chain_id,
            compute_results_hash: HiLo::from_hi_lo(compute_results_hash.hi_lo()),
            query_hash: HiLo::from_hi_lo(query_hash.hi_lo()),
            query_schema: HiLo::from_hi_lo(query_schema.hi_lo()),
            results_root_poseidon,
            promise_subquery_hashes,
        };
        self.payload = Some((keccak_chip, concat_proof_witness));

        CoreBuilderOutput {
            public_instances: logical_pis.into_raw(),
            virtual_table: vec![],
            logical_results: vec![],
        }
    }

    fn virtual_assign_phase1(&mut self, builder: &mut RlcCircuitBuilder<F>) {
        let (keccak, payload) = self.payload.take().unwrap();
        let gate = keccak.gate();
        let rlc = builder.rlc_chip(gate);
        let rlc_pair = builder.rlc_ctx_pair();
        encode_compute_query_phase1(rlc_pair, gate, &rlc, payload);
    }
}

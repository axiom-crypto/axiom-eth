use axiom_codec::{
    constants::USER_MAX_OUTPUTS,
    decoder::native::decode_compute_snark,
    encoder::native::{get_query_hash_v2, get_query_schema_hash},
    types::native::{AxiomV2ComputeQuery, AxiomV2ComputeSnark, AxiomV2DataQuery},
    utils::native::{decode_hilo_to_h256, encode_h256_to_hilo},
    HiLo,
};
use axiom_eth::{
    halo2_base::{
        gates::circuit::CircuitBuilderStage,
        halo2_proofs::{dev::MockProver, poly::commitment::ParamsProver},
        utils::fs::gen_srs,
    },
    halo2curves::bn256::{Fr, G1Affine},
    snark_verifier::pcs::{
        kzg::{KzgAccumulator, LimbsEncoding},
        AccumulatorEncoding,
    },
    snark_verifier_sdk::{
        gen_pk,
        halo2::{
            aggregation::{AggregationCircuit, VerifierUniversality},
            gen_snark_shplonk,
        },
        NativeLoader, Snark, BITS, LIMBS, SHPLONK,
    },
    utils::{
        build_utils::pinning::CircuitPinningInstructions,
        component::ComponentCircuit,
        snark_verifier::{AggregationCircuitParams, NUM_FE_ACCUMULATOR},
    },
};

use ethers_core::{types::H256, utils::keccak256};
use itertools::Itertools;
#[cfg(test)]
use test_log::test;

use crate::{
    components::results::types::{CircuitOutputResultsRoot, LogicOutputResultsRoot},
    utils::client_circuit::metadata::AxiomV2CircuitMetadata,
    verify_compute::{
        tests::utils::dummy_compute_snark,
        types::{
            CircuitInputVerifyCompute, CoreParamsVerifyCompute, LogicalPublicInstanceVerifyCompute,
        },
        utils::{
            get_onchain_vk_from_protocol, verify_snark, write_onchain_vkey, UserCircuitParams,
            DEFAULT_CLIENT_METADATA, DEFAULT_USER_PARAMS,
        },
    },
};

use super::{get_test_result, prepare_mock_circuit, prepare_prover_circuit, test_compute_circuit};

fn test_compute_app_snark(
    k: u32,
    user_params: UserCircuitParams,
    subquery_results: LogicOutputResultsRoot,
    result_len: u16,
) -> Snark {
    let app_params = gen_srs(k);
    let compute_app = test_compute_circuit(k, user_params, subquery_results, result_len as usize);
    let pk = gen_pk(&app_params, &compute_app, None);
    gen_snark_shplonk(&app_params, &pk, compute_app, None::<&str>)
}

// this one doesn't have instances in special format
// Note: when `snark` has many public instances, the aggregation circuit needs to do many Poseidon hashes. There are ways to mitigate this if you only reformat the aggregation circuit's public instances to be the correct format: there is no strict requirement on the public instances of the snark to be aggregated
pub fn test_aggregation_circuit(
    agg_circuit_params: AggregationCircuitParams,
    snark: Snark,
) -> AggregationCircuit {
    let params = gen_srs(agg_circuit_params.degree);
    let mut circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Mock,
        agg_circuit_params,
        &params,
        [snark],
        VerifierUniversality::None,
    );
    circuit.expose_previous_instances(false);
    circuit
}

fn get_metadata(agg_circuit_params: AggregationCircuitParams) -> AxiomV2CircuitMetadata {
    AxiomV2CircuitMetadata {
        version: 0,
        num_instance: vec![DEFAULT_CLIENT_METADATA.num_instance[0] + NUM_FE_ACCUMULATOR as u32],
        num_challenge: vec![0],
        is_aggregation: true,
        num_advice_per_phase: vec![agg_circuit_params.num_advice as u16],
        num_lookup_advice_per_phase: vec![agg_circuit_params.num_lookup_advice as u8],
        num_rlc_columns: 0,
        num_fixed: agg_circuit_params.num_fixed as u8,
        max_outputs: USER_MAX_OUTPUTS as u16,
    }
}

fn get_test_input(
    app_snark: Snark,
    source_chain_id: u64,
    subquery_results: LogicOutputResultsRoot,
    result_len: u16,
    agg_k: u32,
) -> (CoreParamsVerifyCompute, CircuitInputVerifyCompute) {
    let agg_circuit_params = AggregationCircuitParams {
        degree: agg_k,
        num_advice: 20,
        num_lookup_advice: 2,
        num_fixed: 1,
        lookup_bits: agg_k as usize - 1,
    };
    let agg_params = gen_srs(agg_k);
    let subquery_results = CircuitOutputResultsRoot::<Fr>::try_from(subquery_results).unwrap();
    let client_metadata = get_metadata(agg_circuit_params);

    let agg_compute_snark = {
        let agg_circuit = test_aggregation_circuit(agg_circuit_params, app_snark);
        // let stats = agg_circuit.builder.statistics();
        // dbg!(stats.gate.total_advice_per_phase);
        // dbg!(stats.gate.total_fixed);
        // dbg!(stats.total_lookup_advice_per_phase);
        let pk = gen_pk(&agg_params, &agg_circuit, None);
        gen_snark_shplonk(&agg_params, &pk, agg_circuit, None::<&str>)
    };
    dbg!(&client_metadata);
    let core_params = CoreParamsVerifyCompute::new(
        subquery_results.results.len(),
        agg_params.get_g()[0],
        client_metadata,
        agg_compute_snark.protocol.preprocessed.len(),
    );
    println!("agg_compute_snark.protocol.preprocessed.len(): {}", core_params.preprocessed_len());

    (
        core_params,
        CircuitInputVerifyCompute::new(
            source_chain_id,
            subquery_results,
            true,
            result_len,
            agg_compute_snark,
        ),
    )
}

// this test involves creating aggregation snark with real prover so it is heavy, but we should still include it in the CI
#[test]
fn test_verify_compute_agg_mock() -> anyhow::Result<()> {
    let (_input_results, data_results) = get_test_result::<Fr>();
    let num_subqueries = data_results.num_subqueries;
    let result_len = num_subqueries as u16;

    let compute_app_snark =
        test_compute_app_snark(14, DEFAULT_USER_PARAMS, data_results.clone(), result_len);
    let source_chain_id = 1;
    let agg_k = 20;
    let (core_params, input) =
        get_test_input(compute_app_snark, source_chain_id, data_results.clone(), result_len, agg_k);

    // additional preparation for instance checks later
    let subqueries =
        data_results.results[..num_subqueries].iter().map(|r| r.subquery.clone()).collect();
    let agg_compute_snark = input.compute_snark();
    let data_query = AxiomV2DataQuery { source_chain_id, subqueries };
    let compute_vkey = get_onchain_vk_from_protocol(
        &agg_compute_snark.protocol,
        core_params.client_metadata().clone(),
    );
    let agg_instances = &agg_compute_snark.instances[0];
    let KzgAccumulator { lhs, rhs } =
        <LimbsEncoding<LIMBS, BITS> as AccumulatorEncoding<G1Affine, NativeLoader>>::from_repr(
            &agg_instances[..NUM_FE_ACCUMULATOR].iter().collect_vec(),
        )
        .unwrap();
    let compute_results = agg_instances[NUM_FE_ACCUMULATOR..]
        .chunks(2)
        .take(result_len as usize)
        .map(|c| decode_hilo_to_h256(HiLo::from_hi_lo([c[0], c[1]])))
        .collect_vec();
    let compute_snark = AxiomV2ComputeSnark {
        kzg_accumulator: Some((lhs, rhs)),
        compute_results,
        proof_transcript: agg_compute_snark.proof.clone(),
    };
    let compute_proof = compute_snark.encode()?.into();
    let compute_query = AxiomV2ComputeQuery {
        k: agg_k as u8,
        result_len,
        vkey: write_onchain_vkey(&compute_vkey).unwrap(),
        compute_proof,
    };

    let circuit_k = 19u32;
    let keccak_f_capacity = 200;
    let circuit = prepare_mock_circuit(core_params, circuit_k as usize, keccak_f_capacity, input);
    let instances = circuit.get_public_instances();

    // check instances:
    // check query hash and query schema calculation
    let logic_pis = instances.other.clone();
    let LogicalPublicInstanceVerifyCompute {
        query_hash, query_schema, compute_results_hash, ..
    } = logic_pis.try_into()?;
    let native_query_schema =
        get_query_schema_hash(compute_query.k, compute_query.result_len, &compute_query.vkey)?;
    assert_eq!(&query_schema, &encode_h256_to_hilo(&native_query_schema));
    let native_query_hash = get_query_hash_v2(source_chain_id, &data_query, &compute_query)?;
    // dbg!(native_query_hash);
    assert_eq!(&query_hash, &encode_h256_to_hilo(&native_query_hash));
    let compute_snark =
        decode_compute_snark(&mut &compute_query.compute_proof[..], result_len, true)?;
    let encode_results = compute_snark.compute_results.iter().map(|r| r.0.to_vec()).concat();
    let native_results_hash = H256(keccak256(encode_results));
    assert_eq!(&compute_results_hash, &encode_h256_to_hilo(&native_results_hash));

    // actually run mockprover
    MockProver::run(circuit_k, &circuit, vec![instances.into()]).unwrap().assert_satisfied();
    Ok(())
}

#[test]
fn test_verify_compute_agg_prover() -> anyhow::Result<()> {
    let (_input_results, data_results) = get_test_result::<Fr>();
    let num_subqueries = data_results.num_subqueries;
    let result_len = num_subqueries as u16;

    // === create proving key for the VerifyCompute circuit ===
    // we test that only the aggregation circuit's shape matters, whereas the original snark to be aggregated can have different shapes
    let mut user_params = DEFAULT_USER_PARAMS;
    user_params.num_advice_cols += 1;
    let app_k = 12;
    let agg_k = 20;
    let compute_app_snark = dummy_compute_snark(&gen_srs(app_k), user_params, "./data");
    let (core_params, input) = get_test_input(compute_app_snark, 0, data_results.clone(), 0, agg_k);

    let circuit_k = 19u32;
    let circuit = prepare_mock_circuit(core_params, circuit_k as usize, 200, input);

    let kzg_params = gen_srs(circuit_k);
    let pk = gen_pk(&kzg_params, &circuit, None);
    let rlc_pinning = circuit.pinning();
    // ===== end proving key generation ====

    let compute_app_snark =
        test_compute_app_snark(14, DEFAULT_USER_PARAMS, data_results.clone(), result_len);
    let (core_params, input) =
        get_test_input(compute_app_snark, 1, data_results, result_len, agg_k);

    let circuit = prepare_prover_circuit(core_params, rlc_pinning, 200, input);

    let snark = gen_snark_shplonk(&kzg_params, &pk, circuit, None::<&str>);
    let dk = (kzg_params.get_g()[0], kzg_params.g2(), kzg_params.s_g2());
    verify_snark(&dk.into(), &snark)?;

    Ok(())
}

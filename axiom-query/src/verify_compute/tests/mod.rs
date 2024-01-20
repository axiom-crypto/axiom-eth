#![allow(clippy::field_reassign_with_default)]
use std::{collections::HashMap, fs::File, panic::catch_unwind};

use axiom_codec::{
    constants::*,
    decoder::native::decode_compute_snark,
    encoder::native::{get_query_hash_v2, get_query_schema_hash},
    types::{
        field_elements::{FieldSubqueryResult, SUBQUERY_KEY_LEN},
        native::{AxiomV2ComputeQuery, AxiomV2DataQuery},
    },
    utils::native::encode_h256_to_hilo,
};
use axiom_eth::{
    halo2_base::{
        gates::circuit::builder::BaseCircuitBuilder,
        halo2_proofs::dev::MockProver,
        utils::fs::{gen_srs, read_params},
    },
    halo2_proofs::poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    halo2curves::bn256::{Bn256, Fr},
    keccak::{
        promise::generate_keccak_shards_from_calls,
        types::{ComponentTypeKeccak, OutputKeccakShard},
    },
    utils::{
        build_utils::pinning::RlcCircuitPinning,
        component::{
            promise_loader::single::PromiseLoaderParams, ComponentCircuit,
            ComponentPromiseResultsInMerkle, ComponentType,
        },
    },
    zkevm_hashes::keccak::vanilla::keccak_packed_multi::get_num_keccak_f,
};

use ethers_core::{
    types::{Bytes, H256},
    utils::keccak256,
};
use hex::FromHex;
use itertools::Itertools;
#[cfg(test)]
use test_log::test;

use crate::{
    components::{
        dummy_rlc_circuit_params,
        results::{
            self,
            tests::test_capacity,
            types::{
                CircuitInputResultsRootShard, CircuitOutputResultsRoot, LogicOutputResultsRoot,
            },
        },
    },
    verify_compute::{
        tests::utils::{default_compute_snark, InputVerifyCompute},
        types::{CircuitInputVerifyCompute, LogicalPublicInstanceVerifyCompute},
        utils::{reconstruct_snark_from_compute_query, DEFAULT_CLIENT_METADATA},
        utils::{verify_snark, UserCircuitParams, DEFAULT_USER_PARAMS},
    },
    Field,
};

use super::{circuit::ComponentCircuitVerifyCompute, types::CoreParamsVerifyCompute};

use utils::get_base_input;

/// needs to be large enough to fit results and data instances
pub const DUMMY_USER_K: u32 = 14;

/// Test when computeSnark is aggregation circuit
pub mod aggregation;
/// test prove module
pub mod prove;
/// Testing specific utils
pub mod utils;

pub fn get_test_result<F: Field>() -> (CircuitInputResultsRootShard<F>, LogicOutputResultsRoot) {
    let mut capacity = test_capacity();
    if capacity.total > USER_MAX_OUTPUTS {
        capacity.total = USER_MAX_OUTPUTS;
    }
    let (input, output, _) = results::tests::get_test_input(capacity).unwrap();
    (input, output)
}

pub fn test_compute_circuit<F: Field>(
    k: u32,
    user_params: UserCircuitParams,
    subquery_results: LogicOutputResultsRoot,
    result_len: usize,
) -> BaseCircuitBuilder<F> {
    let circuit_params = user_params.base_circuit_params(k as usize);
    let mut builder = BaseCircuitBuilder::new(false).use_params(circuit_params);
    // let range = builder.range_chip();

    let ctx = builder.main(0);

    let mut compute_results = vec![];
    let mut data_instances = vec![];
    for result in subquery_results.results.into_iter().take(subquery_results.num_subqueries) {
        let result = FieldSubqueryResult::<F>::try_from(result).unwrap();
        let data_instance = ctx.assign_witnesses(result.to_fixed_array());
        compute_results.extend(data_instance[SUBQUERY_KEY_LEN..][..2].to_vec());
        data_instances.extend(data_instance);
    }
    assert!(compute_results.len() >= 2 * result_len);
    compute_results.truncate(2 * result_len);
    compute_results.resize_with(2 * USER_MAX_OUTPUTS, || ctx.load_witness(F::ZERO));

    let mut assigned_instance = compute_results;
    assigned_instance.extend(data_instances);
    assigned_instance
        .resize_with(DEFAULT_USER_PARAMS.num_instances(), || ctx.load_witness(F::ZERO));
    builder.assigned_instances[0] = assigned_instance;

    builder
}

fn prepare_mock_circuit(
    core_params: CoreParamsVerifyCompute,
    k: usize,
    keccak_f_capacity: usize,
    input: CircuitInputVerifyCompute,
) -> ComponentCircuitVerifyCompute {
    let mut rlc_params = dummy_rlc_circuit_params(k);
    rlc_params.base.lookup_bits = Some(k - 1);
    let loader_params = PromiseLoaderParams::new_for_one_shard(keccak_f_capacity);
    let mut circuit = ComponentCircuitVerifyCompute::new(core_params, loader_params, rlc_params);
    circuit.feed_input(Box::new(input)).unwrap();
    circuit.calculate_params();
    let promise_results = HashMap::from_iter([(
        ComponentTypeKeccak::<Fr>::get_type_id(),
        ComponentPromiseResultsInMerkle::from_single_shard(
            generate_keccak_shards_from_calls(&circuit, keccak_f_capacity)
                .unwrap()
                .into_logical_results(),
        ),
    )]);
    circuit.fulfill_promise_results(&promise_results).unwrap();
    circuit
}

fn prepare_prover_circuit(
    core_params: CoreParamsVerifyCompute,
    rlc_pinning: RlcCircuitPinning,
    keccak_f_capacity: usize,
    input: CircuitInputVerifyCompute,
) -> ComponentCircuitVerifyCompute {
    let loader_params = PromiseLoaderParams::new_for_one_shard(keccak_f_capacity);
    let circuit = ComponentCircuitVerifyCompute::prover(core_params, loader_params, rlc_pinning);
    circuit.feed_input(Box::new(input)).unwrap();
    let promise_results = HashMap::from_iter([(
        ComponentTypeKeccak::<Fr>::get_type_id(),
        ComponentPromiseResultsInMerkle::from_single_shard(
            generate_keccak_shards_from_calls(&circuit, keccak_f_capacity)
                .unwrap()
                .into_logical_results(),
        ),
    )]);
    circuit.fulfill_promise_results(&promise_results).unwrap();
    circuit
}

#[test]
fn test_verify_no_compute_mock() {
    let (_, subquery_results) = get_test_result::<Fr>();
    let result_len = 2; // test different from numSubqueries
    let num_subqueries = subquery_results.num_subqueries;

    let source_chain_id = 1;
    let empty_cq = AxiomV2ComputeQuery {
        k: 0,
        result_len: result_len as u16,
        vkey: vec![],
        compute_proof: Bytes::from([]),
    };
    let logic_input =
        InputVerifyCompute { source_chain_id, subquery_results, compute_query: empty_cq.clone() };

    let circuit_k = 19u32;

    let (core_params, input) =
        CircuitInputVerifyCompute::reconstruct(logic_input.clone(), &gen_srs(DUMMY_USER_K))
            .unwrap();
    let circuit = prepare_mock_circuit(core_params, circuit_k as usize, 200, input);
    let instances = circuit.get_public_instances();

    let subqueries = logic_input.subquery_results.results[..num_subqueries]
        .iter()
        .map(|r| r.subquery.clone())
        .collect();
    let data_query = AxiomV2DataQuery { source_chain_id, subqueries };

    // check query hash and query schema calculation
    let logic_pis = instances.other.clone();
    let LogicalPublicInstanceVerifyCompute {
        query_hash, query_schema, compute_results_hash, ..
    } = logic_pis.try_into().unwrap();
    assert_eq!(&query_schema, &encode_h256_to_hilo(&H256::zero()));
    let native_query_hash = get_query_hash_v2(source_chain_id, &data_query, &empty_cq).unwrap();
    assert_eq!(&query_hash, &encode_h256_to_hilo(&native_query_hash));
    let encode_results = logic_input.subquery_results.results[..result_len]
        .iter()
        .map(|r| r.value.to_vec())
        .concat();
    let native_results_hash = H256(keccak256(encode_results));
    assert_eq!(&compute_results_hash, &encode_h256_to_hilo(&native_results_hash));
    MockProver::run(circuit_k, &circuit, vec![instances.into()]).unwrap().assert_satisfied();
}

#[test]
fn test_verify_compute_mock() -> anyhow::Result<()> {
    let (_input_results, data_results) = get_test_result::<Fr>();
    let result_len = data_results.num_subqueries;

    let app_k = 14;
    let app_params = gen_srs(app_k);
    let logic_input = get_base_input(
        &app_params,
        USER_MAX_OUTPUTS,
        test_compute_circuit(app_k, DEFAULT_USER_PARAMS, data_results.clone(), result_len),
        data_results,
        1,
        result_len,
    )?;
    // serde_json::to_writer(File::create("data/test/input_results_root.json")?, &input_results)?;
    serde_json::to_writer(File::create("data/test/input_verify_compute.json")?, &logic_input)?;

    let circuit_k = 19u32;

    let (core_params, input) =
        CircuitInputVerifyCompute::reconstruct(logic_input.clone(), &app_params)?;
    let circuit = prepare_mock_circuit(core_params, circuit_k as usize, 200, input);
    let instances = circuit.get_public_instances();

    let source_chain_id = logic_input.source_chain_id;
    let num_subqueries = logic_input.subquery_results.num_subqueries;
    let subqueries = logic_input.subquery_results.results[..num_subqueries]
        .iter()
        .map(|r| r.subquery.clone())
        .collect();
    let data_query = AxiomV2DataQuery { source_chain_id, subqueries };
    let compute_query = logic_input.compute_query;
    /*dbg!(data_query.keccak());
    {
        let vkey = compute_query.vkey.chunks(32).map(H256::from_slice).collect_vec();
        dbg!(vkey);
    }
    */
    // dbg!(compute_query.compute_proof.len());
    // dbg!(&Bytes::from(compute_query.encode().unwrap()));
    // dbg!(compute_query.keccak());

    // check query hash and query schema calculation
    let logic_pis = instances.other.clone();
    let LogicalPublicInstanceVerifyCompute {
        query_hash, query_schema, compute_results_hash, ..
    } = logic_pis.try_into()?;
    let native_query_schema =
        get_query_schema_hash(compute_query.k, result_len as u16, &compute_query.vkey)?;
    assert_eq!(&query_schema, &encode_h256_to_hilo(&native_query_schema));
    let native_query_hash = get_query_hash_v2(source_chain_id, &data_query, &compute_query)?;
    // dbg!(native_query_hash);
    assert_eq!(&query_hash, &encode_h256_to_hilo(&native_query_hash));
    let compute_snark =
        decode_compute_snark(&mut &compute_query.compute_proof[..], result_len as u16, false)?;
    let encode_results = compute_snark.compute_results.iter().map(|r| r.0.to_vec()).concat();
    let native_results_hash = H256(keccak256(encode_results));
    assert_eq!(&compute_results_hash, &encode_h256_to_hilo(&native_results_hash));
    MockProver::run(circuit_k, &circuit, vec![instances.into()]).unwrap().assert_satisfied();
    Ok(())
}

#[test]
fn test_verify_compute_prover_full() -> anyhow::Result<()> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let (_, data_results) = get_test_result::<Fr>();
    let result_len = data_results.num_subqueries;
    let max_num_subqueries = data_results.results.len();

    let app_k = 14;
    let app_params = gen_srs(app_k);
    let logic_input = get_base_input(
        &app_params,
        USER_MAX_OUTPUTS,
        test_compute_circuit(app_k, DEFAULT_USER_PARAMS, data_results.clone(), result_len),
        data_results,
        1,
        result_len,
    )?;
    let mut f = File::create(format!("{cargo_manifest_dir}/data/test/input_verify_compute.json",))?;
    serde_json::to_writer(&mut f, &logic_input)?;
    let res = catch_unwind(|| {
        prove::verify_compute_prover(
            logic_input.clone(),
            max_num_subqueries,
            "verify_compute",
            None,
            200,
        )
        .unwrap()
    });
    std::fs::remove_file(format!("{cargo_manifest_dir}/data/test/verify_compute.pk")).ok();
    std::fs::remove_file(format!("{cargo_manifest_dir}/data/test/verify_compute.snark")).ok();
    let (snark, _, _) = res.unwrap();
    let dk = (app_params.get_g()[0], app_params.g2(), app_params.s_g2());
    verify_snark(&dk.into(), &snark)?;

    Ok(())
}

#[test]
#[ignore = "integration test"]
fn test_verify_compute_prepare_for_agg() -> anyhow::Result<()> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let data_results: LogicOutputResultsRoot = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/data/test/output_result_root_for_agg.json",
    ))?)?;
    let result_len = 2;

    let app_k = 14;
    let app_params = read_params(app_k);
    let logic_input = get_base_input(
        &app_params,
        USER_MAX_OUTPUTS,
        test_compute_circuit(app_k, DEFAULT_USER_PARAMS, data_results.clone(), result_len),
        data_results,
        1,
        result_len,
    )?;
    serde_json::to_writer(
        File::create(format!("{cargo_manifest_dir}/data/test/input_verify_compute_for_agg.json"))?,
        &logic_input,
    )?;

    let circuit_k = 19u32;
    let (core_params, input) =
        CircuitInputVerifyCompute::reconstruct(logic_input.clone(), &app_params)?;
    let keccak_cap = 200;
    let circuit = prepare_mock_circuit(core_params, circuit_k as usize, keccak_cap, input);
    let keccak_shard = generate_keccak_shards_from_calls(&circuit, keccak_cap)?;
    serde_json::to_writer(
        File::create(format!(
            "{cargo_manifest_dir}/data/test/verify_compute_promise_results_keccak_for_agg.json"
        ))?,
        &keccak_shard,
    )?;
    Ok(())
}

#[test]
#[ignore = "integration test"]
fn test_merge_keccak_shards_for_agg() -> anyhow::Result<()> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let header_keccak: OutputKeccakShard = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/data/test/header_promise_results_keccak_for_agg.json"
    ))?)?;
    let results_root_keccak: OutputKeccakShard = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/data/test/results_root_promise_results_keccak_for_agg.json"
    ))?)?;
    let verify_compute_keccak: OutputKeccakShard = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/data/test/verify_compute_promise_results_keccak_for_agg.json"
    ))?)?;
    let responses = std::iter::empty()
        .chain(header_keccak.responses)
        .chain(results_root_keccak.responses)
        .chain(verify_compute_keccak.responses)
        .collect::<Vec<_>>();
    let mut used_cap = 0;
    for r in &responses {
        used_cap += get_num_keccak_f(r.0.len());
    }
    assert!(used_cap <= 200);
    let merged = OutputKeccakShard { responses, capacity: 200 };
    serde_json::to_writer(
        File::create(format!(
            "{cargo_manifest_dir}/data/test/promise_results_keccak_for_agg.json"
        ))?,
        &merged,
    )?;
    Ok(())
}

#[test]
#[ignore = "integration test"]
fn test_verify_compute_prover_for_agg() -> anyhow::Result<()> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let logic_input: InputVerifyCompute = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/data/test/input_verify_compute_for_agg.json"
    ))?)?;
    let promise_keccak: OutputKeccakShard = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/data/test/promise_results_keccak_for_agg.json"
    ))?)?;
    let keccak_cap = promise_keccak.capacity;
    prove::verify_compute_prover(
        logic_input.clone(),
        logic_input.subquery_results.results.len(),
        "verify_compute_for_agg",
        Some(promise_keccak),
        keccak_cap,
    )?;
    Ok(())
}

#[test]
fn test_circuit_metadata_encode() {
    assert_eq!(
        DEFAULT_CLIENT_METADATA.encode().unwrap().as_bytes(),
        &Vec::from_hex("0001000009000100000004010000010080000000000000000000000000000000").unwrap()
    );
}

impl CircuitInputVerifyCompute {
    /// **Assumptions:**
    /// - The generator `params_for_dummy.get_g()[0]` should match that of the trusted setup used to generate `input.compute_query` if there is a compute query.
    /// - If there is no compute query (so compute_query.k == 0), then a dummy compute snark is generated using `params_for_dummy` with [DEFAULT_CLIENT_METADATA].
    pub fn reconstruct(
        input: InputVerifyCompute,
        params_for_dummy: &ParamsKZG<Bn256>,
    ) -> anyhow::Result<(CoreParamsVerifyCompute, Self)> {
        let InputVerifyCompute { source_chain_id, subquery_results, compute_query } = input;

        let compute_query_result_len = compute_query.result_len;
        let nonempty_compute_query = compute_query.k != 0;
        let (compute_snark, client_metadata) = if compute_query.k == 0 {
            (default_compute_snark(params_for_dummy), DEFAULT_CLIENT_METADATA.clone())
        } else {
            reconstruct_snark_from_compute_query(subquery_results.clone(), compute_query)?
        };
        let subquery_results = CircuitOutputResultsRoot::try_from(subquery_results)?;
        let circuit_params = CoreParamsVerifyCompute::new(
            subquery_results.results.len(),
            params_for_dummy.get_g()[0],
            client_metadata,
            compute_snark.protocol.preprocessed.len(),
        );
        println!(
            "compute_snark.protocol.preprocessed.len(): {}",
            circuit_params.preprocessed_len()
        );

        Ok((
            circuit_params,
            Self::new(
                source_chain_id,
                subquery_results,
                nonempty_compute_query,
                compute_query_result_len,
                compute_snark,
            ),
        ))
    }
}

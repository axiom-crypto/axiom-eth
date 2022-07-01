use super::setup_provider;
use crate::{
    batch_query::{
        aggregation::{HashStrategy, PoseidonAggregationCircuit},
        response::{
            account::{
                MultiAccountCircuit, ACCOUNT_INSTANCE_SIZE, ACCOUNT_KECCAK_ROOT_INDICES,
                ACCOUNT_POSEIDON_ROOT_INDICES,
            },
            row_consistency::{RowConsistencyCircuit, ROW_CIRCUIT_NUM_INSTANCES},
        },
        tests::{
            account::native_account_instance, get_latest_block_number,
            storage::get_full_storage_inputs_nouns,
        },
    },
    providers::get_account_queries,
    storage::{EthBlockStorageInput, ACCOUNT_PROOF_MAX_DEPTH},
    util::{circuit::PreCircuit, EthConfigParams},
    AggregationPreCircuit, Network,
};
use ethers_core::types::{Address, H256};
use ethers_providers::{Http, Provider};
use ff::Field;
use halo2_base::{
    gates::builder::CircuitBuilderStage,
    halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr},
    utils::fs::gen_srs,
};
use itertools::Itertools;
use rand::{thread_rng, Rng};
use rand_core::OsRng;
use snark_verifier_sdk::{gen_pk, halo2::gen_snark_shplonk, Snark, LIMBS};
use std::env::set_var;
use test_log::test;

/*fn create_account_snark(
    provider: &Provider<Http>,
    block_responses: Vec<(Fr, H256)>,
    queries: Vec<(u64, Address)>,
    not_empty: Vec<bool>,
) -> Snark {
    let params = EthConfigParams::from_path("configs/tests/account_query.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let input = MultiAccountCircuit::from_provider(provider, block_responses, queries, not_empty);
    let params = gen_srs(k);
    let circuit = input.create_circuit(CircuitBuilderStage::Mock, None, &params);
    let pk = gen_pk(&params, &circuit, None);
    gen_snark_shplonk(&params, &pk, circuit, None::<&str>)
}

fn test_mock_account_aggregation_depth(
    block_responses: Vec<(Fr, H256)>,
    queries: Vec<(u64, &str)>,
    not_empty: Vec<bool>,
    depth: usize,
) {
    let provider = setup_provider();
    let chunk_size = queries.len() >> depth;
    assert!(chunk_size != 0, "depth too large");
    let queries = queries
        .into_iter()
        .map(|(block_number, address)| {
            let address = address.parse().unwrap();
            (block_number, address)
        })
        .collect_vec();
    let snarks = block_responses
        .chunks(chunk_size)
        .zip(queries.chunks(chunk_size).zip(not_empty.chunks(chunk_size)))
        .into_iter()
        .map(|(block_responses, (queries, not_empty))| {
            (
                create_account_snark(
                    &provider,
                    block_responses.to_vec(),
                    queries.to_vec(),
                    not_empty.to_vec(),
                ),
                false,
            )
        })
        .collect_vec();

    let input = MerkleAggregationCircuit::new(
        HashStrategy::Tree,
        snarks,
        ACCOUNT_INSTANCE_SIZE,
        ACCOUNT_POSEIDON_ROOT_INDICES.to_vec(),
        ACCOUNT_KECCAK_ROOT_INDICES.to_vec(),
    );
    let agg_k = 20;
    let config_params = EthConfigParams {
        degree: agg_k,
        lookup_bits: Some(agg_k as usize - 1),
        unusable_rows: 50,
        ..Default::default()
    };
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&config_params).unwrap());
    let agg_params = gen_srs(agg_k);
    let circuit =
        input.create_circuit(CircuitBuilderStage::Mock, None, agg_k as usize - 1, &agg_params);

    let mut instance = circuit.instance();
    MockProver::run(agg_k, &circuit, vec![instance.clone()]).unwrap().assert_satisfied();
    // now check against expected
    let queries = get_account_queries(&provider, queries, ACCOUNT_PROOF_MAX_DEPTH);
    let native_instance = native_account_instance(&block_responses, &queries, &not_empty);
    assert_eq!(instance.split_off(4 * LIMBS), native_instance);
}

#[test]
fn test_mock_account_aggregation() {
    let mut queries = vec![
        (17143006, "0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B"),
        (17143000, "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
        (15000000, "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
        (15411056, "0x1c479675ad559DC151F6Ec7ed3FbF8ceE79582B6"),
    ];
    let address = "0x756F45E3FA69347A9A973A725E3C98bC4db0b5a0";
    let mut rng = thread_rng();
    let latest = get_latest_block_number();
    let queries2: Vec<_> = (0..4).map(|_| (rng.gen_range(0..latest), address)).collect();
    queries.extend(queries2);

    let block_resp = queries.iter().map(|_| (Fr::random(OsRng), H256::random())).collect_vec();
    let not_empty = vec![true; queries.len()];

    test_mock_account_aggregation_depth(block_resp.clone(), queries.clone(), not_empty.clone(), 1);
    test_mock_account_aggregation_depth(block_resp, queries, not_empty, 2);
}*/

fn test_mock_row_consistency_aggregation_depth(
    responses: Vec<EthBlockStorageInput>,
    block_not_empty: Vec<bool>,
    account_not_empty: Vec<bool>,
    storage_not_empty: Vec<bool>,
    depth: usize,
) {
    assert!(responses.len().is_power_of_two());
    let chunk_size = responses.len() >> depth;
    assert!(chunk_size != 0, "depth too large");
    let k = 20 - depth as u32;
    let params = gen_srs(k);
    let mut pk = None;
    let snarks =
        responses
            .chunks(chunk_size)
            .zip(block_not_empty.chunks(chunk_size).zip(
                account_not_empty.chunks(chunk_size).zip(storage_not_empty.chunks(chunk_size)),
            ))
            .into_iter()
            .map(|(response, (block_not_empty, (account_not_empty, storage_not_empty)))| {
                let input = RowConsistencyCircuit::new(
                    response.to_vec(),
                    block_not_empty.to_vec(),
                    account_not_empty.to_vec(),
                    storage_not_empty.to_vec(),
                    Network::Mainnet,
                );
                let circuit = input.create_circuit(CircuitBuilderStage::Mock, None, k);
                if pk.is_none() {
                    pk = Some(gen_pk(&params, &circuit, None));
                }
                (gen_snark_shplonk(&params, pk.as_ref().unwrap(), circuit, None::<&str>), false)
            })
            .collect_vec();

    let input =
        PoseidonAggregationCircuit::new(HashStrategy::Tree, snarks, ROW_CIRCUIT_NUM_INSTANCES);
    let agg_k = 20;
    let agg_params = gen_srs(agg_k);
    let lookup_bits = agg_k as usize - 1;
    set_var("LOOKUP_BITS", lookup_bits.to_string());
    let circuit = AggregationPreCircuit::create_circuit(
        input,
        CircuitBuilderStage::Mock,
        None,
        lookup_bits,
        &agg_params,
    );
    let mut instance = circuit.instance();
    MockProver::run(agg_k, &circuit, vec![instance.clone()]).unwrap().assert_satisfied();

    // now check against non-aggregated
    let input = RowConsistencyCircuit::new(
        responses,
        block_not_empty,
        account_not_empty,
        storage_not_empty,
        Network::Mainnet,
    );
    set_var("LOOKUP_BITS", "0");
    let circuit = input.create_circuit(CircuitBuilderStage::Mock, None, agg_k);
    assert_eq!(instance.split_off(4 * LIMBS), circuit.instance());
}

#[test]
fn test_mock_row_consistency_aggregation_nouns() {
    let responses = get_full_storage_inputs_nouns(128);
    let mut rng = thread_rng();
    let block_not_empty = responses.iter().map(|_| rng.gen_bool(0.8)).collect_vec();
    let account_not_empty = block_not_empty.iter().map(|ne| rng.gen_bool(0.8) && *ne).collect_vec();
    let storage_not_empty =
        account_not_empty.iter().map(|ne| rng.gen_bool(0.8) && *ne).collect_vec();
    test_mock_row_consistency_aggregation_depth(
        responses.clone(),
        block_not_empty.clone(),
        account_not_empty.clone(),
        storage_not_empty.clone(),
        1,
    );
    test_mock_row_consistency_aggregation_depth(
        responses,
        block_not_empty,
        account_not_empty,
        storage_not_empty,
        3,
    );
}

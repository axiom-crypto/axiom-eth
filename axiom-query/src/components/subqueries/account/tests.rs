use std::{marker::PhantomData, str::FromStr};

use axiom_codec::types::{field_elements::AnySubqueryResult, native::HeaderSubquery};
use axiom_eth::{
    block_header::STATE_ROOT_INDEX,
    halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr},
    keccak::{promise::generate_keccak_shards_from_calls, types::ComponentTypeKeccak},
    providers::{setup_provider, storage::json_to_mpt_input},
    utils::component::{
        promise_loader::single::PromiseLoaderParams, ComponentCircuit,
        ComponentPromiseResultsInMerkle, ComponentType,
    },
};
use ethers_core::types::{Address, Chain, H256};
use ethers_providers::Middleware;
use futures::future::join_all;
use itertools::Itertools;
use rand::{rngs::StdRng, Rng};
use rand_core::SeedableRng;
use tokio;

use crate::components::{
    dummy_rlc_circuit_params,
    subqueries::{
        block_header::{
            tests::get_latest_block_number,
            types::{ComponentTypeHeaderSubquery, OutputHeaderShard},
        },
        common::shard_into_component_promise_results,
    },
};

use super::{
    circuit::{ComponentCircuitAccountSubquery, CoreParamsAccountSubquery},
    types::{CircuitInputAccountShard, CircuitInputAccountSubquery},
};

pub const ACCOUNT_PROOF_MAX_DEPTH: usize = 13;

async fn test_mock_account_subqueries(
    k: u32,
    network: Chain,
    subqueries: Vec<(u64, &str, usize)>, // (blockNum, addr, fieldIdx)
    keccak_f_capacity: usize,
) -> ComponentCircuitAccountSubquery<Fr> {
    let _ = env_logger::builder().is_test(true).try_init();

    let _provider = setup_provider(network);
    let provider = &_provider;
    let requests =
        join_all(subqueries.into_iter().map(|(block_num, addr, field_idx)| async move {
            let addr = Address::from_str(addr).unwrap();
            let block = provider.get_block(block_num).await.unwrap().unwrap();
            let proof = provider.get_proof(addr, vec![], Some(block_num.into())).await.unwrap();
            let mut proof = json_to_mpt_input(proof, ACCOUNT_PROOF_MAX_DEPTH, 0);
            proof.acct_pf.root_hash = block.state_root;
            CircuitInputAccountSubquery {
                block_number: block_num,
                field_idx: field_idx as u32,
                proof,
            }
        }))
        .await;

    let mut promise_header = OutputHeaderShard {
        results: requests
            .iter()
            .map(|r| AnySubqueryResult {
                subquery: HeaderSubquery {
                    block_number: r.block_number as u32,
                    field_idx: STATE_ROOT_INDEX as u32,
                },
                value: r.proof.acct_pf.root_hash,
            })
            .collect(),
    };
    // shard_into_component_promise_results::<Fr, ComponentTypeHeaderSubquery<Fr>>(promise_header);
    // add in an extra one just to test lookup table
    promise_header.results.push(AnySubqueryResult {
        subquery: HeaderSubquery { block_number: 0x9165ed, field_idx: 4 },
        value: H256::from_str("0xec4c8ec02281c196e3f882b4061c05f4f0843a0eaf72a3ee4715077220934bbc")
            .unwrap(),
    });

    let header_capacity = promise_header.len();

    let circuit_params = dummy_rlc_circuit_params(k as usize);
    let mut circuit = ComponentCircuitAccountSubquery::new(
        CoreParamsAccountSubquery {
            capacity: requests.len(),
            max_trie_depth: ACCOUNT_PROOF_MAX_DEPTH,
        },
        (
            PromiseLoaderParams::new_for_one_shard(keccak_f_capacity),
            PromiseLoaderParams::new_for_one_shard(header_capacity),
        ),
        circuit_params,
    );

    let input = CircuitInputAccountShard::<Fr> { requests, _phantom: PhantomData };
    circuit.feed_input(Box::new(input)).unwrap();
    circuit.calculate_params();

    let promises = [
        (
            ComponentTypeKeccak::<Fr>::get_type_id(),
            ComponentPromiseResultsInMerkle::from_single_shard(
                generate_keccak_shards_from_calls(&circuit, keccak_f_capacity)
                    .unwrap()
                    .into_logical_results(),
            ),
        ),
        (
            ComponentTypeHeaderSubquery::<Fr>::get_type_id(),
            shard_into_component_promise_results::<Fr, ComponentTypeHeaderSubquery<Fr>>(
                promise_header.into(),
            ),
        ),
    ]
    .into_iter()
    .collect();
    circuit.fulfill_promise_results(&promises).unwrap();

    let instances: Vec<Fr> = circuit.get_public_instances().into();
    MockProver::run(k, &circuit, vec![instances]).unwrap().assert_satisfied();
    circuit
}

#[tokio::test]
async fn test_mock_account_subqueries_simple() {
    let k = 18;
    let subqueries = vec![
        (17143006, "0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B", 0),
        (17143000, "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", 1),
        (15000000, "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", 2),
        (15411056, "0x1c479675ad559DC151F6Ec7ed3FbF8ceE79582B6", 3),
        (18320885, "0x0000a26b00c1F0DF003000390027140000fAa719", 0), // Opensea: fees 3
        (18320885, "0x00005EA00Ac477B1030CE78506496e8C2dE24bf5", 0), // Seadrop
        (18320885, "0x000000008924D42d98026C656545c3c1fb3ad31C", 0), // Seadrop factory
    ];
    let _circuit = test_mock_account_subqueries(k, Chain::Mainnet, subqueries, 200).await;
    // TODO: validate field values
}

// this test takes a while
#[tokio::test]
async fn test_mock_account_subqueries_vanity() {
    let k = 19;
    let latest = 18320885;
    let mut rng = StdRng::seed_from_u64(0);
    let subqueries = (0..32)
        .flat_map(|_| {
            vec![
                (
                    rng.gen_range(15303574..latest),
                    "0x0000a26b00c1F0DF003000390027140000fAa719",
                    rng.gen_range(0..4),
                ), // Opensea: fees 3
                (
                    rng.gen_range(15527904..latest),
                    "0x00005EA00Ac477B1030CE78506496e8C2dE24bf5",
                    rng.gen_range(0..4),
                ), // Seadrop
                (
                    rng.gen_range(16836342..latest),
                    "0x000000008924D42d98026C656545c3c1fb3ad31C",
                    rng.gen_range(0..4),
                ), // Seadrop factory
            ]
        })
        .collect_vec();
    let _circuit = test_mock_account_subqueries(k, Chain::Mainnet, subqueries, 2800).await;
}

#[tokio::test]
async fn test_mock_account_subqueries_genesis() {
    let network = Chain::Mainnet;
    // address existing in block 0
    let address = "0x756F45E3FA69347A9A973A725E3C98bC4db0b5a0";
    let mut rng = StdRng::seed_from_u64(1);
    let latest = get_latest_block_number(network).await;
    let mut subqueries: Vec<_> =
        (0..7).map(|_| (rng.gen_range(0..latest), address, rng.gen_range(0..4))).collect();
    subqueries.push((0, address, 0));
    let _circuit = test_mock_account_subqueries(18, network, subqueries, 300).await;
}

#[tokio::test]
async fn test_mock_eoa_account_subqueries() {
    let network = Chain::Mainnet;
    let subqueries: Vec<_> = vec![
        (18320885, "0x5cC0d3B4926D5430946Ea1b60eA2B27974485921", 0),
        (18320885, "0x5cC0d3B4926D5430946Ea1b60eA2B27974485921", 1),
        (18320885, "0x5cC0d3B4926D5430946Ea1b60eA2B27974485921", 2),
        (18320885, "0x5cC0d3B4926D5430946Ea1b60eA2B27974485921", 3),
    ];
    let _circuit = test_mock_account_subqueries(18, network, subqueries, 50).await;
}

#[tokio::test]
async fn test_mock_empty_account_subqueries() {
    let network = Chain::Mainnet;
    let subqueries: Vec<_> = vec![
        (18320885, "0x000000008924D42d98026C656545c3c1fb3ad31B", 0), // empty account
        (18320885, "0x000000008924D42d98026C656545c3c1fb3ad31B", 1),
        (18320885, "0x000000008924D42d98026C656545c3c1fb3ad31B", 2),
        (18320885, "0x000000008924D42d98026C656545c3c1fb3ad31B", 3),
    ];
    let _circuit = test_mock_account_subqueries(18, network, subqueries, 50).await;
}

// Goerli is dead
// #[tokio::test]
// async fn test_mock_empty_account_subqueries2() {
//     let network = Chain::Goerli;
//     // non-inclusion ends in extension node
//     let subqueries: Vec<_> = vec![(9173678, "0x8dde5d4a8384f403f888e1419672d94c570440c9", 0)];
//     let _circuit = test_mock_account_subqueries(18, network, subqueries, 50).await;
// }

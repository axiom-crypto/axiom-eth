use std::{marker::PhantomData, str::FromStr};

use axiom_codec::types::{field_elements::AnySubqueryResult, native::AccountSubquery};
use axiom_eth::{
    halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr},
    keccak::{promise::generate_keccak_shards_from_calls, types::ComponentTypeKeccak},
    mpt::KECCAK_RLP_EMPTY_STRING,
    providers::{setup_provider, storage::json_to_mpt_input},
    utils::component::{
        promise_loader::single::PromiseLoaderParams, ComponentCircuit,
        ComponentPromiseResultsInMerkle, ComponentType,
    },
};
use ethers_core::{
    types::{Address, Chain, H256},
    utils::keccak256,
};
use ethers_providers::Middleware;
use futures::future::join_all;
use itertools::Itertools;
use rand::{rngs::StdRng, Rng};
use rand_core::SeedableRng;
use tokio;

use crate::components::{
    dummy_rlc_circuit_params,
    subqueries::{
        account::{
            types::{ComponentTypeAccountSubquery, OutputAccountShard},
            STORAGE_ROOT_INDEX,
        },
        block_header::tests::get_latest_block_number,
        common::shard_into_component_promise_results,
        storage::types::CircuitInputStorageSubquery,
    },
};

use super::{
    circuit::{ComponentCircuitStorageSubquery, CoreParamsStorageSubquery},
    types::CircuitInputStorageShard,
};

pub const STORAGE_PROOF_MAX_DEPTH: usize = 13;

async fn test_mock_storage_subqueries(
    k: u32,
    network: Chain,
    subqueries: Vec<(u64, &str, H256)>, // (blockNum, addr, slot)
) -> ComponentCircuitStorageSubquery<Fr> {
    let _ = env_logger::builder().is_test(true).try_init();

    let _provider = setup_provider(network);
    let provider = &_provider;
    let (requests, storage_hashes): (Vec<CircuitInputStorageSubquery>, Vec<H256>) =
        join_all(subqueries.into_iter().map(|(block_num, addr, slot)| async move {
            let addr = Address::from_str(addr).unwrap();
            let proof = provider.get_proof(addr, vec![slot], Some(block_num.into())).await.unwrap();
            let storage_hash = if proof.storage_hash.is_zero() {
                // RPC provider may give zero storage hash for empty account, but the correct storage hash should be the null root = keccak256(0x80)
                H256::from_slice(&KECCAK_RLP_EMPTY_STRING)
            } else {
                proof.storage_hash
            };
            assert_eq!(proof.storage_proof.len(), 1, "Storage proof should have length 1 exactly");
            let proof = json_to_mpt_input(proof, 0, STORAGE_PROOF_MAX_DEPTH);
            (CircuitInputStorageSubquery { block_number: block_num, proof }, storage_hash)
        }))
        .await
        .into_iter()
        .unzip();

    let promise_account = OutputAccountShard {
        results: requests
            .iter()
            .zip_eq(storage_hashes)
            .map(|(r, storage_hash)| AnySubqueryResult {
                subquery: AccountSubquery {
                    block_number: r.block_number as u32,
                    field_idx: STORAGE_ROOT_INDEX as u32,
                    addr: r.proof.addr,
                },
                value: storage_hash,
            })
            .collect(),
    };

    let keccak_f_capacity = 1200;
    let account_capacity = promise_account.results.len();

    let circuit_params = dummy_rlc_circuit_params(k as usize);
    let mut circuit = ComponentCircuitStorageSubquery::new(
        CoreParamsStorageSubquery {
            capacity: requests.len(),
            max_trie_depth: STORAGE_PROOF_MAX_DEPTH,
        },
        (
            PromiseLoaderParams::new_for_one_shard(keccak_f_capacity),
            PromiseLoaderParams::new_for_one_shard(account_capacity),
        ),
        circuit_params,
    );

    let input = CircuitInputStorageShard::<Fr> { requests, _phantom: PhantomData };
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
            ComponentTypeAccountSubquery::<Fr>::get_type_id(),
            shard_into_component_promise_results::<Fr, ComponentTypeAccountSubquery<Fr>>(
                promise_account.into(),
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
async fn test_mock_storage_subqueries_slot0() {
    let k = 18;
    let subqueries = vec![
        (17143006, "0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B", H256::zero()),
        (17143000, "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", H256::zero()),
        (16356350, "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB", H256::zero()),
        (15411056, "0x1c479675ad559DC151F6Ec7ed3FbF8ceE79582B6", H256::zero()),
    ];
    test_mock_storage_subqueries(k, Chain::Mainnet, subqueries).await;
}

#[tokio::test]
async fn test_mock_storage_subqueries_uni_v3() {
    let k = 18;
    let network = Chain::Mainnet;
    let mut rng = StdRng::seed_from_u64(0);
    let address = "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640"; // uniswap v3 eth-usdc 5bps pool
    let latest = get_latest_block_number(network).await;
    let subqueries = [0, 1, 2, 8]
        .map(|x| (rng.gen_range(12376729..latest), address, H256::from_low_u64_be(x)))
        .to_vec();
    test_mock_storage_subqueries(k, network, subqueries).await;
}

#[tokio::test]
async fn test_mock_storage_subqueries_mapping() {
    let k = 19;
    let network = Chain::Mainnet;
    let mut rng = StdRng::seed_from_u64(0);
    let address = "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB"; // cryptopunks
    let slots = (0..8).map(|x| {
        let mut bytes = [0u8; 64];
        bytes[31] = x;
        bytes[63] = 10;
        H256::from_slice(&keccak256(bytes))
    });
    let latest = get_latest_block_number(Chain::Mainnet).await;
    let subqueries: Vec<_> =
        slots.map(|slot| (rng.gen_range(3914495..latest), address, slot)).collect();
    test_mock_storage_subqueries(k, network, subqueries).await;
}

// some of the slots will be empty, we test that the value returned is 0
#[tokio::test]
async fn test_mock_storage_subqueries_empty() {
    let k = 20;
    let network = Chain::Mainnet;
    let mut rng = StdRng::seed_from_u64(0);
    let address = "0xbb9bc244d798123fde783fcc1c72d3bb8c189413"; // TheDAO Token

    // don't use random for re-producibility
    let latest = 18317207; // get_latest_block_number(Chain::Mainnet).await;
    let subqueries: Vec<_> = (0..64)
        .map(|_| (rng.gen_range(1428757..latest), address, H256::random_using(&mut rng)))
        .collect();
    test_mock_storage_subqueries(k, network, subqueries[19..20].to_vec()).await;
}

#[tokio::test]
async fn test_mock_storage_subqueries_empty_precompile() {
    let k = 18;
    let subqueries = vec![
        (17143006, "0x0000000000000000000000000000000000000000", H256::zero()),
        (17143000, "0x0000000000000000000000000000000000000001", H256::from_low_u64_be(1)),
        (16356350, "0x0000000000000000000000000000000000000002", H256::from_low_u64_be(2)),
        (15411056, "0x0000000000000000000000000000000000000003", H256::from_low_u64_be(3)),
    ];
    test_mock_storage_subqueries(k, Chain::Mainnet, subqueries).await;
}

#[tokio::test]
async fn test_mock_storage_subqueries_empty_account() {
    let k = 18;
    let subqueries =
        vec![(4_000_000, "0xF57252Fc4ff36D8d10B0b83d8272020D2B8eDd55", H256::from_low_u64_be(295))];
    test_mock_storage_subqueries(k, Chain::Sepolia, subqueries).await;
}

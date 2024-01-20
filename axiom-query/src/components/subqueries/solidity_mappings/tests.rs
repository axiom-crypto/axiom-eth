use std::str::FromStr;

use axiom_codec::{
    types::{
        field_elements::AnySubqueryResult,
        native::{SolidityNestedMappingSubquery, StorageSubquery},
    },
    utils::native::u256_to_h256,
};
use axiom_eth::{
    halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr},
    keccak::{promise::generate_keccak_shards_from_calls, types::ComponentTypeKeccak},
    providers::setup_provider,
    utils::component::{
        promise_loader::single::PromiseLoaderParams, ComponentCircuit,
        ComponentPromiseResultsInMerkle, ComponentType,
    },
};
use ethers_core::{
    types::{Address, Chain, H256, U256},
    utils::keccak256,
};
use ethers_providers::Middleware;
use futures::future::join_all;
use tokio;

use crate::components::{
    dummy_rlc_circuit_params,
    subqueries::{
        common::shard_into_component_promise_results,
        storage::types::{ComponentTypeStorageSubquery, OutputStorageShard},
    },
};

use super::{
    circuit::{
        ComponentCircuitSolidityNestedMappingSubquery, CoreParamsSolidityNestedMappingSubquery,
    },
    types::CircuitInputSolidityNestedMappingShard,
};

async fn test_mock_storage_subqueries(
    k: u32,
    network: Chain,
    subqueries: Vec<(u64, &str, &str, Vec<H256>)>, // (blockNum, addr, mappingSlot, mappingKeys)
) -> ComponentCircuitSolidityNestedMappingSubquery<Fr> {
    let _ = env_logger::builder().is_test(true).try_init();

    let _provider = setup_provider(network);
    let provider = &_provider;
    let (requests, storage_results): (Vec<_>, Vec<_>) =
        join_all(subqueries.into_iter().map(|(block_num, addr, mapping_slot, keys)| async move {
            let addr = Address::from_str(addr).unwrap();
            let mapping_slot = U256::from_str(mapping_slot).unwrap();
            let mut slot = u256_to_h256(&mapping_slot);
            for key in keys.iter() {
                slot = H256(keccak256(&[key.as_bytes(), slot.as_bytes()].concat()));
            }
            let proof = provider.get_proof(addr, vec![slot], Some(block_num.into())).await.unwrap();
            let depth = keys.len();
            let value = u256_to_h256(&proof.storage_proof[0].value);
            (
                SolidityNestedMappingSubquery {
                    block_number: block_num as u32,
                    addr,
                    mapping_slot,
                    mapping_depth: depth as u8,
                    keys,
                },
                AnySubqueryResult {
                    subquery: StorageSubquery {
                        block_number: block_num as u32,
                        addr,
                        slot: U256::from_big_endian(&slot.0),
                    },
                    value,
                },
            )
        }))
        .await
        .into_iter()
        .unzip();

    let promise_storage = OutputStorageShard { results: storage_results };
    let storage_capacity = promise_storage.results.len();
    let keccak_f_capacity = 200;

    let circuit_params = dummy_rlc_circuit_params(k as usize);
    let mut circuit = ComponentCircuitSolidityNestedMappingSubquery::new(
        CoreParamsSolidityNestedMappingSubquery { capacity: requests.len() },
        (
            PromiseLoaderParams::new_for_one_shard(keccak_f_capacity),
            PromiseLoaderParams::new_for_one_shard(storage_capacity),
        ),
        circuit_params,
    );

    let input = CircuitInputSolidityNestedMappingShard::<Fr> {
        requests: requests.into_iter().map(|r| r.into()).collect(),
    };
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
            ComponentTypeStorageSubquery::<Fr>::get_type_id(),
            shard_into_component_promise_results::<Fr, ComponentTypeStorageSubquery<Fr>>(
                promise_storage.into(),
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
async fn test_mock_solidity_nested_mapping_uni_v3_factory() {
    let k = 18;
    let usdc_eth_500 = vec![
        Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap().into(),
        Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap().into(),
        H256::from_low_u64_be(500),
    ];
    let eth_usdc_500 = vec![
        Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap().into(),
        Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap().into(),
        H256::from_low_u64_be(500),
    ];

    let subqueries = vec![
        (
            17143006,
            "0x1F98431c8aD98523631AE4a59f267346ea31F984",
            "0x05", /*getPool*/
            usdc_eth_500,
        ),
        (
            18331196,
            "0x1F98431c8aD98523631AE4a59f267346ea31F984",
            "0x05", /*getPool*/
            eth_usdc_500,
        ),
    ];
    test_mock_storage_subqueries(k, Chain::Mainnet, subqueries).await;
}

use std::{marker::PhantomData, str::FromStr};

use anyhow::anyhow;
use axiom_codec::{
    special_values::{
        RECEIPT_BLOCK_NUMBER_FIELD_IDX, RECEIPT_DATA_IDX_OFFSET, RECEIPT_LOGS_BLOOM_IDX_OFFSET,
        RECEIPT_LOG_IDX_OFFSET, RECEIPT_TOPIC_IDX_OFFSET, RECEIPT_TX_INDEX_FIELD_IDX,
        RECEIPT_TX_TYPE_FIELD_IDX,
    },
    types::{
        field_elements::AnySubqueryResult,
        native::{HeaderSubquery, ReceiptSubquery},
    },
};
use axiom_eth::{
    block_header::RECEIPT_ROOT_INDEX,
    halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr},
    keccak::{promise::generate_keccak_shards_from_calls, types::ComponentTypeKeccak},
    mpt::MPTInput,
    providers::{
        receipt::{construct_rc_tries_from_full_blocks, get_block_with_receipts},
        setup_provider,
        transaction::get_tx_key_from_index,
    },
    receipt::{calc_max_val_len, EthReceiptChipParams, EthReceiptInput},
    utils::component::{
        promise_loader::single::PromiseLoaderParams, ComponentCircuit,
        ComponentPromiseResultsInMerkle, ComponentType,
    },
};
use cita_trie::Trie;
use ethers_core::types::{Chain, H256};
use ethers_providers::Middleware;
use futures::future::join_all;
use itertools::Itertools;
use serde::Serialize;
use tokio;

use crate::components::{
    dummy_rlc_circuit_params,
    subqueries::{
        block_header::types::{ComponentTypeHeaderSubquery, OutputHeaderShard},
        common::shard_into_component_promise_results,
    },
};

use super::{
    circuit::{ComponentCircuitReceiptSubquery, CoreParamsReceiptSubquery},
    types::{CircuitInputReceiptShard, CircuitInputReceiptSubquery},
};

/// transaction index is within u16, so rlp(txIndex) is at most 3 bytes => 6 nibbles
pub const RECEIPT_PROOF_MAX_DEPTH: usize = 6;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Params {
    block_number: String,
}

#[derive(Serialize)]
struct Request {
    id: u8,
    jsonrpc: String,
    method: String,
    params: Vec<Params>,
}

async fn test_mock_receipt_subqueries(
    k: u32,
    network: Chain,
    subqueries: Vec<(&str, usize, usize, &str)>, // txHash, field_or_log_idx, topic_or_data_or_address_idx, event_schema
    max_data_byte_len: usize,
    max_log_num: usize,
) -> ComponentCircuitReceiptSubquery<Fr> {
    let _ = env_logger::builder().is_test(true).try_init();

    let _provider = setup_provider(network);
    let provider = &_provider;
    let requests = join_all(subqueries.into_iter().map(
        |(tx_hash, field_idx, tda_idx, event_schema)| async move {
            let tx_hash = H256::from_str(tx_hash).unwrap();
            let event_schema = H256::from_str(event_schema).unwrap();
            let tx = provider.get_transaction(tx_hash).await.unwrap().unwrap();
            // let rc = provider.get_transaction_receipt(tx_hash).await.unwrap().unwrap();
            // dbg!(rc.logs_bloom);
            let block_number = tx.block_number.unwrap().as_u32();
            let tx_idx = tx.transaction_index.unwrap().as_u32() as u16;
            ReceiptSubquery {
                block_number,
                tx_idx,
                field_or_log_idx: field_idx as u32,
                topic_or_data_or_address_idx: tda_idx as u32,
                event_schema,
            }
        },
    ))
    .await;

    let block_nums = requests.iter().map(|r| r.block_number as u64).sorted().dedup().collect_vec();
    let blocks = join_all(block_nums.iter().map(|&block_num| async move {
        get_block_with_receipts(provider, block_num, None).await.unwrap()
    }))
    .await;

    let chip_params = EthReceiptChipParams {
        max_data_byte_len,
        max_log_num,
        topic_num_bounds: (0, 4),
        network: None,
    };
    let receipt_rlp_max_byte_len =
        calc_max_val_len(max_data_byte_len, max_log_num, chip_params.topic_num_bounds);

    let rc_tries = construct_rc_tries_from_full_blocks(blocks.clone()).unwrap();
    let mut requests_in_circuit = Vec::with_capacity(requests.len());
    for subquery in requests {
        let block_number = subquery.block_number as u64;
        let tx_idx = subquery.tx_idx as usize;
        let tx_key = get_tx_key_from_index(tx_idx);
        let db = rc_tries
            .get(&block_number)
            .ok_or_else(|| {
                anyhow!("Subquery block number {block_number} not in provided full blocks")
            })
            .unwrap();
        let trie = &db.trie;
        let rc_rlps = &db.rc_rlps;
        let proof = trie.get_proof(&tx_key).unwrap();
        let value = rc_rlps
            .get(tx_idx)
            .ok_or_else(|| anyhow!("Receipt index {tx_idx} not in block {block_number}"))
            .unwrap();
        let mpt_proof = MPTInput {
            path: (&tx_key).into(),
            value: value.to_vec(),
            root_hash: db.root,
            proof,
            slot_is_empty: false,
            value_max_byte_len: receipt_rlp_max_byte_len,
            max_depth: RECEIPT_PROOF_MAX_DEPTH,
            max_key_byte_len: 3,
            key_byte_len: Some(tx_key.len()),
        };
        let rc_proof = EthReceiptInput { idx: tx_idx, proof: mpt_proof };
        requests_in_circuit.push(CircuitInputReceiptSubquery {
            block_number,
            proof: rc_proof,
            field_or_log_idx: subquery.field_or_log_idx,
            topic_or_data_or_address_idx: subquery.topic_or_data_or_address_idx,
            event_schema: subquery.event_schema,
        });
    }

    let promise_header = OutputHeaderShard {
        results: blocks
            .iter()
            .map(|block| AnySubqueryResult {
                subquery: HeaderSubquery {
                    block_number: block.number.as_u32(),
                    field_idx: RECEIPT_ROOT_INDEX as u32,
                },
                value: block.receipts_root,
            })
            .collect(),
    };
    let keccak_f_capacity = 200;
    let header_capacity = promise_header.len();

    let circuit_params = dummy_rlc_circuit_params(k as usize);
    let mut circuit = ComponentCircuitReceiptSubquery::new(
        CoreParamsReceiptSubquery {
            chip_params,
            capacity: requests_in_circuit.len(),
            max_trie_depth: RECEIPT_PROOF_MAX_DEPTH,
        },
        (
            PromiseLoaderParams::new_for_one_shard(keccak_f_capacity),
            PromiseLoaderParams::new_for_one_shard(header_capacity),
        ),
        circuit_params,
    );

    let input =
        CircuitInputReceiptShard::<Fr> { requests: requests_in_circuit, _phantom: PhantomData };
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
async fn test_mock_receipt_subqueries_simple() {
    let k = 18;
    let zero = "0x0000000000000000000000000000000000000000000000000000000000000000";
    let subqueries = vec![
        ("0xa85fb48c6cd0b6013c91a3ea93ef73cd3c39845eb258f1d82ef4210c223594f4", 0, 0, zero), // status = fail
        (
            "0xc830e27d1bbfc0ea7f9a86f3debb5d6c6105a6585a44589734b12cb678f843c4",
            RECEIPT_LOGS_BLOOM_IDX_OFFSET + 1,
            0,
            zero,
        ),
        (
            "0xc830e27d1bbfc0ea7f9a86f3debb5d6c6105a6585a44589734b12cb678f843c4",
            RECEIPT_LOG_IDX_OFFSET,
            RECEIPT_TOPIC_IDX_OFFSET + 1,
            "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c", // Deposit (index_topic_1 address dst, uint256 wad)
        ),
        (
            "0xc830e27d1bbfc0ea7f9a86f3debb5d6c6105a6585a44589734b12cb678f843c4",
            RECEIPT_LOG_IDX_OFFSET + 1,
            RECEIPT_TOPIC_IDX_OFFSET + 1,
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // Transfer (index_topic_1 address src, index_topic_2 address dst, uint256 wad)
        ),
        (
            "0xc830e27d1bbfc0ea7f9a86f3debb5d6c6105a6585a44589734b12cb678f843c4",
            RECEIPT_LOG_IDX_OFFSET + 1,
            RECEIPT_DATA_IDX_OFFSET,
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        ),
    ];
    test_mock_receipt_subqueries(k, Chain::Mainnet, subqueries, 200, 10).await;
}

#[tokio::test]
async fn test_mock_receipt_subqueries_pre_eip658() {
    let k = 18;
    let zero = "0x0000000000000000000000000000000000000000000000000000000000000000";
    let subqueries = vec![
        ("0x5be4ebff5bb19b012d8db932e629eda0af068e392758719353db5e0895147f8e", 1, 0, zero), // postState
        ("0x5be4ebff5bb19b012d8db932e629eda0af068e392758719353db5e0895147f8e", 2, 0, zero), // cumulativeGas
        ("0x5be4ebff5bb19b012d8db932e629eda0af068e392758719353db5e0895147f8e", 3, 0, zero), // logsBloom
        (
            "0x5be4ebff5bb19b012d8db932e629eda0af068e392758719353db5e0895147f8e",
            RECEIPT_BLOCK_NUMBER_FIELD_IDX,
            0,
            zero,
        ),
        (
            "0x5be4ebff5bb19b012d8db932e629eda0af068e392758719353db5e0895147f8e",
            RECEIPT_TX_TYPE_FIELD_IDX,
            0,
            zero,
        ),
        (
            "0x5be4ebff5bb19b012d8db932e629eda0af068e392758719353db5e0895147f8e",
            RECEIPT_TX_INDEX_FIELD_IDX,
            0,
            zero,
        ),
        (
            "0x5be4ebff5bb19b012d8db932e629eda0af068e392758719353db5e0895147f8e",
            RECEIPT_LOGS_BLOOM_IDX_OFFSET + 7,
            0,
            zero,
        ),
        (
            "0x5be4ebff5bb19b012d8db932e629eda0af068e392758719353db5e0895147f8e",
            RECEIPT_LOG_IDX_OFFSET,
            0,
            zero,
        ),
        (
            "0x5be4ebff5bb19b012d8db932e629eda0af068e392758719353db5e0895147f8e",
            RECEIPT_LOG_IDX_OFFSET,
            50,
            zero,
        ),
        (
            "0x5be4ebff5bb19b012d8db932e629eda0af068e392758719353db5e0895147f8e",
            RECEIPT_LOG_IDX_OFFSET,
            100 + 63,
            zero,
        ),
        (
            "0x5be4ebff5bb19b012d8db932e629eda0af068e392758719353db5e0895147f8e",
            RECEIPT_LOG_IDX_OFFSET,
            100 + 30,
            "0x92ca3a80853e6663fa31fa10b99225f18d4902939b4c53a9caae9043f6efd004",
        ),
    ];
    test_mock_receipt_subqueries(k, Chain::Mainnet, subqueries, 2048, 2).await;
}

#[cfg(feature = "keygen")]
#[tokio::test]
#[ignore]
async fn test_generate_receipt_shard_pk() {
    use axiom_eth::halo2_base::utils::{fs::read_params, halo2::ProvingKeyGenerator};

    use crate::{global_constants::RECEIPT_TOPIC_BOUNDS, keygen::shard::ShardIntentReceipt};

    let core_params = CoreParamsReceiptSubquery {
        chip_params: EthReceiptChipParams {
            max_data_byte_len: 256,
            max_log_num: 10,
            topic_num_bounds: RECEIPT_TOPIC_BOUNDS,
            network: None,
        },
        capacity: 4,
        max_trie_depth: RECEIPT_PROOF_MAX_DEPTH,
    };
    let loader_params =
        (PromiseLoaderParams::new_for_one_shard(200), PromiseLoaderParams::new_for_one_shard(8));
    let k = 18;
    let intent = ShardIntentReceipt { core_params, loader_params, k, lookup_bits: 8 };
    let kzg_params = read_params(k);
    intent.create_pk_and_pinning(&kzg_params);
}

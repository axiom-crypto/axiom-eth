use std::{marker::PhantomData, str::FromStr};

use axiom_codec::{
    special_values::{TX_CALLDATA_IDX_OFFSET, TX_FUNCTION_SELECTOR_FIELD_IDX},
    types::{
        field_elements::AnySubqueryResult,
        native::{HeaderSubquery, TxSubquery},
    },
};
use axiom_eth::{
    block_header::TX_ROOT_INDEX,
    halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr},
    keccak::{promise::generate_keccak_shards_from_calls, types::ComponentTypeKeccak},
    mpt::MPTInput,
    providers::{
        setup_provider,
        transaction::{
            construct_tx_tries_from_full_blocks, get_tx_key_from_index, BlockWithTransactions,
        },
    },
    transaction::{calc_max_val_len, EthTransactionChipParams, EthTransactionProof},
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
use tokio;

use crate::components::{
    dummy_rlc_circuit_params,
    subqueries::{
        block_header::types::{ComponentTypeHeaderSubquery, OutputHeaderShard},
        common::shard_into_component_promise_results,
    },
};

use super::{
    circuit::{ComponentCircuitTxSubquery, CoreParamsTxSubquery},
    types::{CircuitInputTxShard, CircuitInputTxSubquery},
};

/// transaction index is within u16, so rlp(txIndex) is at most 3 bytes => 6 nibbles
pub const TRANSACTION_PROOF_MAX_DEPTH: usize = 6;

async fn test_mock_tx_subqueries(
    k: u32,
    network: Chain,
    subqueries: Vec<(&str, usize)>, // txHash, field_or_calldata_idx
    max_data_byte_len: usize,
    max_access_list_len: usize,
) -> ComponentCircuitTxSubquery<Fr> {
    let _ = env_logger::builder().is_test(true).try_init();

    let _provider = setup_provider(network);
    let provider = &_provider;
    let requests = join_all(subqueries.into_iter().map(|(tx_hash, field_idx)| async move {
        let tx_hash = H256::from_str(tx_hash).unwrap();
        let tx = provider.get_transaction(tx_hash).await.unwrap().unwrap();
        let block_number = tx.block_number.unwrap().as_u32();
        let tx_idx = tx.transaction_index.unwrap().as_u32() as u16;
        TxSubquery { block_number, tx_idx, field_or_calldata_idx: field_idx as u32 }
    }))
    .await;

    let block_nums = requests.iter().map(|r| r.block_number).sorted().dedup().collect_vec();
    let blocks = join_all(block_nums.iter().map(|&block_num| async move {
        let block = provider.get_block_with_txs(block_num as u64).await.unwrap().unwrap();
        BlockWithTransactions::try_from(block).unwrap()
    }))
    .await;

    let promise_header = OutputHeaderShard {
        results: blocks
            .iter()
            .map(|block| AnySubqueryResult {
                subquery: HeaderSubquery {
                    block_number: block.number.as_u32(),
                    field_idx: TX_ROOT_INDEX as u32,
                },
                value: block.transactions_root,
            })
            .collect(),
    };

    let enable_types = [true, true, true];
    let tx_rlp_max_byte_len =
        calc_max_val_len(max_data_byte_len, max_access_list_len, enable_types);

    let tx_tries = construct_tx_tries_from_full_blocks(blocks).unwrap();
    let mut requests_in_circuit = Vec::with_capacity(requests.len());
    for subquery in requests {
        let block_number = subquery.block_number as u64;
        let tx_idx = subquery.tx_idx as usize;
        let tx_key = get_tx_key_from_index(tx_idx);
        let db = tx_tries.get(&block_number).unwrap();
        let trie = &db.trie;
        let tx_rlps = &db.tx_rlps;
        let proof = trie.get_proof(&tx_key).unwrap();
        let value = tx_rlps.get(tx_idx).unwrap();
        let mpt_proof = MPTInput {
            path: (&tx_key).into(),
            value: value.to_vec(),
            root_hash: db.root,
            proof,
            slot_is_empty: false,
            value_max_byte_len: tx_rlp_max_byte_len,
            max_depth: TRANSACTION_PROOF_MAX_DEPTH,
            max_key_byte_len: 3,
            key_byte_len: Some(tx_key.len()),
        };
        let tx_proof = EthTransactionProof { tx_index: tx_idx, proof: mpt_proof };
        requests_in_circuit.push(CircuitInputTxSubquery {
            block_number,
            proof: tx_proof,
            field_or_calldata_idx: subquery.field_or_calldata_idx,
        });
    }

    let keccak_f_capacity = 200;
    let header_capacity = promise_header.results.len();

    let circuit_params = dummy_rlc_circuit_params(k as usize);

    let chip_params = EthTransactionChipParams {
        max_data_byte_len,
        max_access_list_len,
        enable_types: [true, true, true],
        network: None,
    };
    let mut circuit = ComponentCircuitTxSubquery::new(
        CoreParamsTxSubquery {
            chip_params,
            capacity: requests_in_circuit.len(),
            max_trie_depth: TRANSACTION_PROOF_MAX_DEPTH,
        },
        (
            PromiseLoaderParams::new_for_one_shard(keccak_f_capacity),
            PromiseLoaderParams::new_for_one_shard(header_capacity),
        ),
        circuit_params,
    );

    let input = CircuitInputTxShard::<Fr> { requests: requests_in_circuit, _phantom: PhantomData };
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
async fn test_mock_tx_subqueries_simple() {
    let k = 18;
    let subqueries = vec![
        (
            "0x7311924b41863b7d6dbd129dc0890903432a30af831f24697a5c5b522be5088f",
            TX_FUNCTION_SELECTOR_FIELD_IDX,
        ), // transfer
        (
            "0x6a74ccb57011073104c89da78b02229e12c8a4160c5fe1c8278c6a73913ca289",
            TX_FUNCTION_SELECTOR_FIELD_IDX,
        ),
        (
            "0x6a74ccb57011073104c89da78b02229e12c8a4160c5fe1c8278c6a73913ca289",
            TX_CALLDATA_IDX_OFFSET,
        ),
        (
            "0x6a74ccb57011073104c89da78b02229e12c8a4160c5fe1c8278c6a73913ca289",
            TX_CALLDATA_IDX_OFFSET + 1,
        ),
        (
            "0x9524b67377f7ff228fbe31c7edbfb4ba7bb374ceeac54030793b6727d1dc4505",
            TX_FUNCTION_SELECTOR_FIELD_IDX,
        ),
    ];
    test_mock_tx_subqueries(k, Chain::Mainnet, subqueries, 200, 0).await;
}

#[tokio::test]
async fn test_mock_tx_subqueries_legacy_vrs() {
    let k = 18;
    let subqueries = vec![
        ("0xb522100fc065547683da6b3fa5e755e721ffe5cd80f73153327cd5f403e6223c", 8),
        ("0xb522100fc065547683da6b3fa5e755e721ffe5cd80f73153327cd5f403e6223c", 9),
        ("0xb522100fc065547683da6b3fa5e755e721ffe5cd80f73153327cd5f403e6223c", 10),
        ("0xb522100fc065547683da6b3fa5e755e721ffe5cd80f73153327cd5f403e6223c", 11),
    ];
    test_mock_tx_subqueries(k, Chain::Sepolia, subqueries, 4000, 0).await;
}

#[tokio::test]
async fn test_mock_tx_subqueries_eip4844() {
    let k = 18;
    let subqueries = vec![(
        "0x740bbfb65e00b16e496757dfb1c8df1eea101cf9f559f519096d25904b7fa79b",
        TX_FUNCTION_SELECTOR_FIELD_IDX,
    )];
    test_mock_tx_subqueries(k, Chain::Mainnet, subqueries, 200, 0).await;
}

#[cfg(feature = "keygen")]
#[tokio::test]
#[ignore]
async fn test_generate_tx_shard_pk() {
    use axiom_eth::halo2_base::utils::{fs::read_params, halo2::ProvingKeyGenerator};

    use crate::keygen::shard::ShardIntentTx;

    let core_params = CoreParamsTxSubquery {
        chip_params: EthTransactionChipParams {
            max_data_byte_len: 512,
            max_access_list_len: 0,
            enable_types: [true; 3],
            network: None,
        },
        capacity: 4,
        max_trie_depth: TRANSACTION_PROOF_MAX_DEPTH,
    };
    let loader_params =
        (PromiseLoaderParams::new_for_one_shard(200), PromiseLoaderParams::new_for_one_shard(8));
    let k = 18;
    let intent = ShardIntentTx { core_params, loader_params, k, lookup_bits: 8 };
    let kzg_params = read_params(k);
    intent.create_pk_and_pinning(&kzg_params);
}

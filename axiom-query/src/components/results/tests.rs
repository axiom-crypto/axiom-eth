use std::{collections::HashMap, fs::File, str::FromStr};

use anyhow::Result;
use axiom_codec::{
    constants::NUM_SUBQUERY_TYPES,
    encoder::field_elements::{NUM_FE_ANY, NUM_FE_SOLIDITY_NESTED_MAPPING_WITHOUT_KEYS},
    special_values::{
        RECEIPT_LOG_IDX_OFFSET, RECEIPT_TOPIC_IDX_OFFSET, TX_FUNCTION_SELECTOR_FIELD_IDX,
    },
    types::{
        field_elements::{AnySubqueryResult, FlattenedSubqueryResult},
        native::{
            AccountSubquery, AnySubquery, HeaderSubquery, ReceiptSubquery,
            SolidityNestedMappingSubquery, StorageSubquery, Subquery, SubqueryResult, SubqueryType,
            TxSubquery,
        },
    },
    utils::native::u256_to_h256,
};
use axiom_eth::{
    block_header::{EXTRA_DATA_INDEX, RECEIPT_ROOT_INDEX, STATE_ROOT_INDEX, TX_ROOT_INDEX},
    halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr},
    keccak::{promise::generate_keccak_shards_from_calls, types::ComponentTypeKeccak},
    utils::build_utils::pinning::{CircuitPinningInstructions, Halo2CircuitPinning},
    utils::{
        component::{
            promise_loader::{
                comp_loader::SingleComponentLoaderParams,
                multi::{ComponentTypeList, MultiPromiseLoaderParams},
                single::PromiseLoaderParams,
            },
            utils::compute_poseidon,
            ComponentCircuit, ComponentPromiseResultsInMerkle, ComponentType,
            GroupedPromiseResults,
        },
        encode_h256_to_hilo,
    },
};
use ethers_core::types::{Address, Bytes, H256, U256};
use hex::FromHex;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    components::{
        dummy_rlc_circuit_params,
        results::{
            circuit::SubqueryDependencies, table::SubqueryResultsTable,
            types::CircuitInputResultsRootShard,
        },
        subqueries::{
            account::{types::ComponentTypeAccountSubquery, STORAGE_ROOT_INDEX},
            block_header::types::ComponentTypeHeaderSubquery,
            common::{shard_into_component_promise_results, OutputSubqueryShard},
            receipt::types::ComponentTypeReceiptSubquery,
            solidity_mappings::types::ComponentTypeSolidityNestedMappingSubquery,
            storage::types::ComponentTypeStorageSubquery,
            transaction::types::ComponentTypeTxSubquery,
        },
    },
    Field,
};

use super::{
    circuit::{ComponentCircuitResultsRoot, CoreParamsResultRoot},
    types::{
        component_type_id_to_subquery_type, LogicOutputResultsRoot,
        LogicalPublicInstanceResultsRoot,
    },
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Hash, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComponentCapacities {
    pub total: usize,
    pub header: usize,
    pub account: usize,
    pub storage: usize,
    pub tx: usize,
    pub receipt: usize,
    pub solidity_mapping: usize,
    pub keccak: usize,
}
impl ComponentCapacities {
    pub fn to_str_short(&self) -> String {
        format!(
            "{}_{}_{}_{}_{}_{}_{}_{}",
            self.total,
            self.header,
            self.account,
            self.storage,
            self.tx,
            self.receipt,
            self.solidity_mapping,
            self.keccak
        )
    }
}

pub fn get_test_input<F: Field>(
    capacity: ComponentCapacities,
) -> Result<(CircuitInputResultsRootShard<F>, LogicOutputResultsRoot, GroupedPromiseResults<F>)> {
    let mut extra_data = Vec::from_hex("43727578706f6f6c205050532f6e696365686173682d31").unwrap();
    extra_data.resize(32, 0u8);
    let block_number = 9528813;
    let mut header_subqueries = vec![
        (
            HeaderSubquery { block_number, field_idx: 1 },
            H256::from_str("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")?,
        ),
        (
            HeaderSubquery { block_number, field_idx: 71 },
            H256::from_str("0x2a4a0345b08e0c50805158030213038e9205244c5100b7223068018ef1648009")?,
        ),
        (
            HeaderSubquery { block_number, field_idx: EXTRA_DATA_INDEX as u32 },
            H256::from_slice(&extra_data),
        ),
        (
            HeaderSubquery { block_number, field_idx: STATE_ROOT_INDEX as u32 },
            H256::from_str("0x9ce4561dfadb4fb022debc7c013141a36a23d467f4268c0e620a7bba05b174f8")?,
        ),
        (
            HeaderSubquery { block_number, field_idx: TX_ROOT_INDEX as u32 },
            H256::from_str("0xec4c8ec02281c196e3f882b4061c05f4f0843a0eaf72a3ee4715077220934bbc")?,
        ),
        (
            HeaderSubquery { block_number, field_idx: RECEIPT_ROOT_INDEX as u32 },
            H256::from_str("0x0dfecab5d97a4da361b92c29157cd6a5089b55facee007eea16005bfa8d82694")?,
        ),
    ];

    let addr = Address::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7")?;
    let mut acct_subqueries = vec![(
        AccountSubquery { block_number, addr, field_idx: STORAGE_ROOT_INDEX as u32 },
        H256::from_str("0x3bddd93ffcce5169c2ce5d08b91f9fda3ed657dbf3b78beffb44dc833f6308a2")?,
    )];

    let mut storage_subqueries = vec![(
        StorageSubquery {
            block_number,
            addr,
            slot: U256::from_str(
                "0xac33ff75c19e70fe83507db0d683fd3465c996598dc972688b7ace676c89077b",
            )?,
        },
        u256_to_h256(&U256::from_str("0xb532b80")?),
    )];

    let mut solidity_mapping_subqueries = vec![(
        SolidityNestedMappingSubquery {
            block_number,
            addr,
            mapping_slot: U256::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000002",
            )?,
            mapping_depth: 1,
            keys: vec![H256::zero()],
        }, // balances https://evm.storage/eth/9528813/0xdac17f958d2ee523a2206206994597c13d831ec7/balances#map
        u256_to_h256(&U256::from_str("0xb532b80")?),
    )];

    let mut tx_subqueries = vec![(
        TxSubquery {
            block_number,
            tx_idx: 68,
            field_or_calldata_idx: TX_FUNCTION_SELECTOR_FIELD_IDX as u32,
        }, // https://etherscan.io/tx/0x9524b67377f7ff228fbe31c7edbfb4ba7bb374ceeac54030793b6727d1dc4505
        u256_to_h256(&U256::from_str("0x013efd8b")?),
    )];

    let mut receipt_subqueries = vec![(
        ReceiptSubquery {
            block_number,
            tx_idx: 68, // https://etherscan.io/tx/0x9524b67377f7ff228fbe31c7edbfb4ba7bb374ceeac54030793b6727d1dc4505#eventlog
            field_or_log_idx: RECEIPT_LOG_IDX_OFFSET as u32 + 2,
            topic_or_data_or_address_idx: RECEIPT_TOPIC_IDX_OFFSET as u32 + 1,
            event_schema: H256::from_str(
                "0x7f4091b46c33e918a0f3aa42307641d17bb67029427a5369e54b353984238705",
            )?,
        },
        H256::from(Address::from_str("0x263FC4d9Eb6da1ED296ea6d189b41e546a188D8A")?),
    )];
    header_subqueries.truncate(capacity.header);
    acct_subqueries.truncate(capacity.account);
    storage_subqueries.truncate(capacity.storage);
    solidity_mapping_subqueries.truncate(capacity.solidity_mapping);
    tx_subqueries.truncate(capacity.tx);
    receipt_subqueries.truncate(capacity.receipt);

    fn append(
        results: &mut Vec<SubqueryResult>,
        subqueries: &[(impl Into<Subquery> + Clone, H256)],
    ) {
        for (s, v) in subqueries {
            results.push(SubqueryResult { subquery: s.clone().into(), value: v.0.into() })
        }
    }
    fn resize_with_first<T: Clone>(v: &mut Vec<T>, cap: usize) {
        if cap > 0 {
            v.resize(cap, v[0].clone());
        } else {
            v.clear();
        }
    }
    let mut results = vec![];
    // put them in weird order just to test
    append(&mut results, &tx_subqueries);
    append(&mut results, &header_subqueries);
    append(&mut results, &receipt_subqueries);
    append(&mut results, &acct_subqueries);
    append(&mut results, &storage_subqueries);
    append(&mut results, &solidity_mapping_subqueries);
    results.truncate(capacity.total);
    let num_subqueries = results.len();
    resize_with_first(&mut results, capacity.total);
    let _encoded_subqueries: Vec<Bytes> =
        results.iter().map(|r| r.subquery.encode().into()).collect();
    let subquery_hashes: Vec<H256> = results.iter().map(|r| r.subquery.keccak()).collect();

    fn prepare<A: Clone>(results: Vec<(A, H256)>) -> OutputSubqueryShard<A, H256> {
        let results = results.into_iter().map(|(s, v)| AnySubqueryResult::new(s, v)).collect_vec();
        OutputSubqueryShard { results }
    }
    resize_with_first(&mut header_subqueries, capacity.header);
    resize_with_first(&mut acct_subqueries, capacity.account);
    resize_with_first(&mut storage_subqueries, capacity.storage);
    resize_with_first(&mut tx_subqueries, capacity.tx);
    resize_with_first(&mut receipt_subqueries, capacity.receipt);
    resize_with_first(&mut solidity_mapping_subqueries, capacity.solidity_mapping);

    let promise_header = prepare(header_subqueries);
    let promise_account = prepare(acct_subqueries);
    let promise_storage = prepare(storage_subqueries);
    let promise_tx = prepare(tx_subqueries);
    let promise_receipt = prepare(receipt_subqueries);
    let promise_solidity_mapping = prepare(solidity_mapping_subqueries);

    let mut promise_results = HashMap::new();
    for (type_id, pr) in SubqueryDependencies::<F>::get_component_type_ids().into_iter().zip_eq([
        shard_into_component_promise_results::<F, ComponentTypeHeaderSubquery<F>>(
            promise_header.convert_into(),
        ),
        shard_into_component_promise_results::<F, ComponentTypeAccountSubquery<F>>(
            promise_account.convert_into(),
        ),
        shard_into_component_promise_results::<F, ComponentTypeStorageSubquery<F>>(
            promise_storage.convert_into(),
        ),
        shard_into_component_promise_results::<F, ComponentTypeTxSubquery<F>>(
            promise_tx.convert_into(),
        ),
        shard_into_component_promise_results::<F, ComponentTypeReceiptSubquery<F>>(
            promise_receipt.convert_into(),
        ),
        shard_into_component_promise_results::<F, ComponentTypeSolidityNestedMappingSubquery<F>>(
            promise_solidity_mapping.convert_into(),
        ),
    ]) {
        // filter out empty shards with capacity = 0.
        if !pr.shards()[0].1.is_empty() {
            promise_results.insert(type_id, pr);
        }
    }

    Ok((
        CircuitInputResultsRootShard::<F> {
            subqueries: SubqueryResultsTable::<F>::new(
                results.clone().into_iter().map(|r| r.try_into().unwrap()).collect_vec(),
            ),
            num_subqueries: F::from(num_subqueries as u64),
        },
        LogicOutputResultsRoot { results, subquery_hashes, num_subqueries },
        promise_results,
    ))
}

pub const fn test_capacity() -> ComponentCapacities {
    ComponentCapacities {
        total: 32,
        header: 32,
        account: 8,
        storage: 8,
        tx: 8,
        receipt: 8,
        solidity_mapping: 8,
        keccak: 500,
    }
}

#[test]
fn test_mock_results_root() -> anyhow::Result<()> {
    let k = 18;
    let capacity = test_capacity();
    let (input, subquery_results, mut promise_results) = get_test_input(capacity)?;

    let mut enabled_types = [false; NUM_SUBQUERY_TYPES];
    let mut params_per_comp = HashMap::new();
    // reminder: input.promises order is deterministic, from ComponentTypeResultsRoot::subquery_type_ids()
    for (component_type_id, results) in &promise_results {
        if component_type_id == &ComponentTypeKeccak::<Fr>::get_type_id() {
            continue;
        }
        let subquery_type = component_type_id_to_subquery_type::<Fr>(component_type_id).unwrap();
        enabled_types[subquery_type as usize] = true;

        // TODO: Shard capacity shoud come from .get_capactiy.
        params_per_comp.insert(
            component_type_id.clone(),
            SingleComponentLoaderParams::new(0, vec![results.shards()[0].1.len()]),
        );
    }
    let promise_results_params = MultiPromiseLoaderParams { params_per_component: params_per_comp };
    let keccak_f_capacity = capacity.keccak;

    let circuit_params = dummy_rlc_circuit_params(k as usize);
    let mut circuit = ComponentCircuitResultsRoot::new(
        CoreParamsResultRoot { enabled_types, capacity: input.subqueries.len() },
        (PromiseLoaderParams::new_for_one_shard(keccak_f_capacity), promise_results_params),
        circuit_params,
    );
    circuit.feed_input(Box::new(input)).unwrap();
    circuit.calculate_params();
    promise_results.insert(
        ComponentTypeKeccak::<Fr>::get_type_id(),
        ComponentPromiseResultsInMerkle::from_single_shard(
            generate_keccak_shards_from_calls(&circuit, keccak_f_capacity)
                .unwrap()
                .into_logical_results(),
        ),
    );
    circuit.fulfill_promise_results(&promise_results).unwrap();
    let pis = circuit.get_public_instances();
    let LogicalPublicInstanceResultsRoot { results_root_poseidon, commit_subquery_hashes } =
        pis.other.clone().try_into().unwrap();
    assert_eq!(
        (results_root_poseidon, commit_subquery_hashes),
        get_native_results_root_and_subquery_hash_commit(subquery_results.clone())
    );
    let instances: Vec<Fr> = pis.into();
    MockProver::run(k as u32, &circuit, vec![instances]).unwrap().assert_satisfied();
    circuit.pinning().write("configs/test/results_root.json").unwrap();

    Ok(())
}

/// Returns (poseidon_results_root, subquery_hash_commit)
// `subqueryResultsPoseidonRoot`: The Poseidon Merkle root of the padded tree (pad by 0) with
// leaves given by `poseidon(poseidon(type . fieldSubqueryData), value[..])`.
//
// ### Note
// `value` consists of multiple field elements, so the above means
// `poseidon([[subqueryHashPoseidon], value[..]].concat())` with
// `subqueryHashPoseidon := poseidon(type . fieldSubqueryData)` and `fieldSubqueryData` is
// **variable length**.
fn get_native_results_root_and_subquery_hash_commit(results: LogicOutputResultsRoot) -> (Fr, Fr) {
    // note compute_poseidon re-creates poseidon spec, but it doesn't matter for test
    let mut leaves = vec![];
    let mut to_commit = vec![];
    for result in results.results.into_iter().take(results.num_subqueries) {
        to_commit.extend(encode_h256_to_hilo::<Fr>(&result.subquery.keccak()).hi_lo());
        // NUM_FE_ANY[subquery_type] is the length of fieldSubqueryData
        let unencoded_key_len =
            get_num_fe_from_subquery(result.subquery.clone().try_into().unwrap());
        // add 1 for subquery type
        let encoded_key_len = unencoded_key_len + 1;
        let result = FlattenedSubqueryResult::<Fr>::try_from(result).unwrap();
        let key_hash = compute_poseidon(&result.key[..encoded_key_len]);
        let mut buf = vec![key_hash];
        buf.extend(result.value.0);
        leaves.push(compute_poseidon(&buf));
    }
    leaves.resize(leaves.len().next_power_of_two(), Fr::zero());
    while leaves.len() > 1 {
        leaves = leaves.chunks(2).map(compute_poseidon).collect();
    }
    (leaves[0], compute_poseidon(&to_commit))
}

fn get_num_fe_from_subquery(subquery: AnySubquery) -> usize {
    match subquery {
        AnySubquery::SolidityNestedMapping(subquery) => {
            NUM_FE_SOLIDITY_NESTED_MAPPING_WITHOUT_KEYS + 2 * subquery.mapping_depth as usize
        }
        _ => {
            let subquery_type = Subquery::from(subquery).subquery_type;
            NUM_FE_ANY[subquery_type as usize]
        }
    }
}

#[test]
#[ignore = "integration test"]
fn test_mock_results_root_header_only_for_agg() -> anyhow::Result<()> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");

    let k = 18;
    let capacity = ComponentCapacities {
        total: 3,
        header: 3,
        account: 0,
        storage: 0,
        tx: 0,
        receipt: 0,
        solidity_mapping: 0,
        keccak: 200,
    };
    let (input, output, mut promise_results) = get_test_input(capacity)?;

    let mut enabled_types = [false; NUM_SUBQUERY_TYPES];
    enabled_types[SubqueryType::Header as usize] = true;
    let mut params_per_comp = HashMap::new();

    params_per_comp.insert(
        ComponentTypeHeaderSubquery::<Fr>::get_type_id(),
        SingleComponentLoaderParams::new(0, vec![3]),
    );
    let promise_results_params = MultiPromiseLoaderParams { params_per_component: params_per_comp };

    let keccak_f_capacity = capacity.keccak;

    let circuit_params = dummy_rlc_circuit_params(k as usize);
    let mut circuit = ComponentCircuitResultsRoot::new(
        CoreParamsResultRoot { enabled_types, capacity: input.subqueries.len() },
        (PromiseLoaderParams::new_for_one_shard(keccak_f_capacity), promise_results_params),
        circuit_params,
    );
    circuit.feed_input(Box::new(input.clone())).unwrap();
    circuit.calculate_params();

    let keccak_shard = generate_keccak_shards_from_calls(&circuit, keccak_f_capacity)?;
    serde_json::to_writer(
        File::create(format!(
            "{cargo_manifest_dir}/data/test/results_root_promise_results_keccak_for_agg.json"
        ))?,
        &keccak_shard,
    )?;
    promise_results.insert(
        ComponentTypeKeccak::<Fr>::get_type_id(),
        ComponentPromiseResultsInMerkle::from_single_shard(keccak_shard.into_logical_results()),
    );
    circuit.fulfill_promise_results(&promise_results).unwrap();
    let instances: Vec<Fr> = circuit.get_public_instances().into();
    MockProver::run(k as u32, &circuit, vec![instances]).unwrap().assert_satisfied();

    serde_json::to_writer(
        File::create(format!("{cargo_manifest_dir}/data/test/input_result_root_for_agg.json"))?,
        &input,
    )?;
    serde_json::to_writer(
        File::create(format!("{cargo_manifest_dir}/data/test/output_result_root_for_agg.json"))?,
        &output,
    )?;

    circuit.pinning().write("configs/test/results_root_for_agg.json").unwrap();

    Ok(())
}

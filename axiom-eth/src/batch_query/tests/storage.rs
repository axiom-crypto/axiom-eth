use crate::{
    batch_query::{
        hash::{poseidon_tree_root, PoseidonWords},
        response::{
            native::{get_full_storage_response, get_storage_response, FullStorageQuery},
            storage::{MultiStorageCircuit, DEFAULT_STORAGE_QUERY},
        },
        tests::get_latest_block_number,
    },
    providers::get_full_storage_queries,
    rlp::builder::RlcThreadBuilder,
    storage::{
        EthBlockStorageInput, {ACCOUNT_PROOF_MAX_DEPTH, STORAGE_PROOF_MAX_DEPTH},
    },
    util::{encode_addr_to_field, encode_h256_to_field, h256_tree_root, EthConfigParams},
    EthPreCircuit,
};
use ethers_core::{
    types::{Address, H256},
    utils::keccak256,
};
use ff::Field;
use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use itertools::Itertools;
use rand::{thread_rng, Rng};
use rand_chacha::ChaChaRng;
use rand_core::{OsRng, SeedableRng};
use snark_verifier::util::hash::Poseidon;
use snark_verifier_sdk::{halo2::POSEIDON_SPEC, NativeLoader};
use std::{env::set_var, str::FromStr};
use test_log::test;

use super::setup_provider;

fn test_mock_storage_queries(
    block_responses: Vec<(Fr, u32)>,
    acct_responses: Vec<(Fr, Address)>,
    queries: Vec<(u64, &str, H256)>,
    not_empty: Vec<bool>,
) {
    let params = EthConfigParams::from_path("configs/tests/storage_query.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let queries = queries
        .into_iter()
        .map(|(block_number, address, slot)| {
            let address = address.parse().unwrap();
            (block_number, address, slot)
        })
        .collect();

    let input = MultiStorageCircuit::from_provider(
        &setup_provider(),
        block_responses,
        acct_responses,
        queries,
        not_empty.clone(),
    );
    // instance calculation natively for test validation
    let mut poseidon = Poseidon::from_spec(&NativeLoader, POSEIDON_SPEC.clone());
    let block_num_root = poseidon_tree_root(
        &mut poseidon,
        input
            .block_responses
            .iter()
            .map(|(_, num)| PoseidonWords(vec![Fr::from(*num as u64)]))
            .collect(),
        &[],
    );
    let addr_root = poseidon_tree_root(
        &mut poseidon,
        input
            .account_responses
            .iter()
            .map(|(_, addr)| PoseidonWords(vec![encode_addr_to_field::<Fr>(addr)]))
            .collect_vec(),
        &[],
    );
    let (res_p, res_k): (Vec<_>, Vec<_>) = input
        .block_responses
        .iter()
        .zip_eq(input.account_responses.iter())
        .zip_eq(input.queries.iter())
        .zip_eq(not_empty.iter())
        .map(|(((block_response, acct_response), query), not_empty)| {
            let (storage_response, _) = get_storage_response(&mut poseidon, query);
            let (mut pos, mut kec) = get_full_storage_response(
                &mut poseidon,
                *block_response,
                *acct_response,
                storage_response,
            );
            if !not_empty {
                pos = Fr::zero();
                kec = H256([0u8; 32]);
            }
            (pos, kec)
        })
        .unzip();
    let root_p = poseidon_tree_root(&mut poseidon, res_p, &[]);
    let root_k = encode_h256_to_field(&h256_tree_root(&res_k));
    let instance = vec![root_k[0], root_k[1], root_p, block_num_root, addr_root];

    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);

    MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied();
}

#[test]
fn test_mock_storage_queries_slot0() {
    let queries = vec![
        (17143006, "0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B", H256::zero()),
        (17143000, "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", H256::zero()),
        (16356350, "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB", H256::zero()),
        (15411056, "0x1c479675ad559DC151F6Ec7ed3FbF8ceE79582B6", H256::zero()),
    ];
    let mut rng = thread_rng();
    // note that block response is not checked in any way in the circuit, in particular the poseidon and keccak parts don't even need to be consistent!
    let block_responses = queries.iter().map(|_| (Fr::random(OsRng), rng.gen())).collect();
    let acct_responses = queries.iter().map(|_| (Fr::random(OsRng), Address::random())).collect();
    let not_empty = vec![true; queries.len()];
    test_mock_storage_queries(block_responses, acct_responses, queries, not_empty);
}

#[test]
fn test_mock_storage_queries_uni_v3() {
    let address = "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640"; // uniswap v3 eth-usdc 5bps pool
    let mut rng = thread_rng();
    let latest = get_latest_block_number();
    let queries = [0, 1, 2, 8]
        .map(|x| (rng.gen_range(12376729..latest), address, H256::from_low_u64_be(x)))
        .to_vec();
    let block_responses = queries.iter().map(|_| (Fr::random(OsRng), rng.gen())).collect();
    let acct_responses = queries.iter().map(|_| (Fr::random(OsRng), Address::random())).collect();
    let not_empty = vec![true; queries.len()];
    test_mock_storage_queries(block_responses, acct_responses, queries, not_empty);
}

#[test]
fn test_mock_storage_queries_mapping() {
    let address = "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB"; // cryptopunks
    let mut rng = thread_rng();
    let slots = (0..4).map(|x| {
        let mut bytes = [0u8; 64];
        bytes[31] = x;
        bytes[63] = 10;
        H256::from_slice(&keccak256(bytes))
    });
    let latest = get_latest_block_number();
    let queries: Vec<_> =
        slots.map(|slot| (rng.gen_range(3914495..latest), address, slot)).collect();
    let block_responses = queries.iter().map(|_| (Fr::random(OsRng), rng.gen())).collect();
    let acct_responses = queries.iter().map(|_| (Fr::random(OsRng), Address::random())).collect();
    let not_empty = vec![true; queries.len()];
    test_mock_storage_queries(block_responses, acct_responses, queries, not_empty);
}

#[test]
fn test_mock_storage_queries_empty() {
    let address = "0xbb9bc244d798123fde783fcc1c72d3bb8c189413"; // TheDAO Token
    let mut rng = thread_rng();
    let latest = get_latest_block_number();
    let mut queries: Vec<_> = (0..8)
        .map(|_| (rng.gen_range(1428757..latest), address, H256::from_low_u64_be(3)))
        .collect();
    let block_responses = queries.iter().map(|_| (Fr::random(OsRng), rng.gen())).collect();
    let acct_responses = queries.iter().map(|_| (Fr::random(OsRng), Address::random())).collect();
    let mut not_empty = vec![true; queries.len()];
    for (ne, q) in not_empty.iter_mut().zip(queries.iter_mut()).take(4) {
        *ne = false;
        q.2 = H256::random();
    }
    test_mock_storage_queries(block_responses, acct_responses, queries, not_empty);
}

// some of the slots will be empty, we test that the value returned is 0
#[test]
fn test_mock_storage_queries_random() {
    let address = "0xbb9bc244d798123fde783fcc1c72d3bb8c189413"; // TheDAO Token
    let mut rng = ChaChaRng::from_seed([0u8; 32]);
    let latest = get_latest_block_number();
    let queries: Vec<_> =
        (0..8).map(|_| (rng.gen_range(1428757..latest), address, H256::random())).collect();
    let block_responses = queries.iter().map(|_| (Fr::random(OsRng), rng.gen())).collect();
    let acct_responses = queries.iter().map(|_| (Fr::random(OsRng), Address::random())).collect();
    let not_empty = vec![true; queries.len()];
    test_mock_storage_queries(block_responses, acct_responses, queries, not_empty);
}

pub fn get_full_storage_queries_nouns_single_block(
    len: usize,
    block_number: u64,
) -> Vec<FullStorageQuery> {
    let address = "0x9C8fF314C9Bc7F6e59A9d9225Fb22946427eDC03"; // NounsToken
    let address: Address = address.parse().unwrap();
    let mut queries = vec![];
    for i in 0..3 {
        queries.push(FullStorageQuery {
            block_number,
            addr_slots: Some((address, vec![H256::from_low_u64_be(i)])),
        });
    }
    if len <= 3 {
        queries.truncate(len);
    } else {
        for i in 0..len - 3 {
            let mut bytes = [0u8; 64];
            bytes[31] = i as u8;
            bytes[63] = 3; // slot 3 is _owners mapping(uint256 => address)
            let slot = H256::from_slice(&keccak256(bytes));
            queries
                .push(FullStorageQuery { block_number, addr_slots: Some((address, vec![slot])) });
        }
    }
    queries
}

pub fn get_full_storage_queries_nouns(len: usize) -> Vec<FullStorageQuery> {
    let creation_block = 12985438;
    let latest = get_latest_block_number();
    let mut rng = rand::thread_rng();
    let mut queries = vec![];

    let mut remaining_len = len;

    while remaining_len > 0 {
        let block_number: u64 = rng.gen_range(creation_block..latest);
        let current_len = rng.gen_range(1..=remaining_len);
        let mut current_queries =
            get_full_storage_queries_nouns_single_block(current_len, block_number);
        queries.append(&mut current_queries);
        remaining_len -= current_len;
    }
    queries
}

pub fn get_full_storage_inputs_nouns(len: usize) -> Vec<EthBlockStorageInput> {
    let queries = get_full_storage_queries_nouns(len);
    let responses = get_full_storage_queries(
        &setup_provider(),
        queries,
        ACCOUNT_PROOF_MAX_DEPTH,
        STORAGE_PROOF_MAX_DEPTH,
    )
    .unwrap();
    responses.into_iter().map(|response| response.try_into().unwrap()).collect()
}

#[test]
fn test_default_storage_query() {
    let address = Address::from_str("0x01d5b501C1fc0121e1411970fb79c322737025c2").unwrap(); // AxiomV0
    let provider = setup_provider();
    let query: EthBlockStorageInput = get_full_storage_queries(
        &provider,
        vec![FullStorageQuery {
            block_number: 16504035,
            addr_slots: Some((address, vec![H256::zero()])),
        }],
        ACCOUNT_PROOF_MAX_DEPTH,
        STORAGE_PROOF_MAX_DEPTH,
    )
    .unwrap()
    .pop()
    .unwrap()
    .try_into()
    .unwrap();

    assert_eq!(format!("{:?}", query.storage), format!("{:?}", DEFAULT_STORAGE_QUERY.clone()))
}

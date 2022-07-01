use super::setup_provider;
use crate::{
    batch_query::{
        hash::{poseidon_tree_root, PoseidonWords},
        response::{
            account::MultiAccountCircuit,
            native::{get_account_response, get_full_account_response},
        },
        tests::get_latest_block_number,
    },
    rlp::builder::RlcThreadBuilder,
    storage::EthStorageInput,
    util::{encode_h256_to_field, h256_tree_root, EthConfigParams},
    EthPreCircuit,
};
use ethers_core::types::H256;
use ff::Field;
use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use itertools::Itertools;
use rand::{thread_rng, Rng};
use rand_core::OsRng;
use snark_verifier::util::hash::Poseidon;
use snark_verifier_sdk::{halo2::POSEIDON_SPEC, NativeLoader};
use std::env::set_var;
use test_log::test;

pub fn native_account_instance(
    block_responses: &[(Fr, u32)],
    queries: &[EthStorageInput],
    not_empty: &[bool],
) -> Vec<Fr> {
    // instance calculation natively for test validation
    let mut poseidon = Poseidon::from_spec(&NativeLoader, POSEIDON_SPEC.clone());
    let block_numbers =
        block_responses.iter().map(|res| PoseidonWords(vec![Fr::from(res.1 as u64)])).collect_vec();
    let block_num_root_p = poseidon_tree_root(&mut poseidon, block_numbers, &[]);
    let (res_p, res_k): (Vec<_>, Vec<_>) = block_responses
        .iter()
        .zip_eq(queries.iter())
        .zip_eq(not_empty.iter())
        .map(|((block_response, query), not_empty)| {
            let (acct_res, _) = get_account_response(&mut poseidon, query);
            let (mut pos, mut kec) =
                get_full_account_response(&mut poseidon, *block_response, acct_res);
            if !not_empty {
                pos = Fr::zero();
                kec = H256([0u8; 32]);
            }
            (pos, kec)
        })
        .unzip();
    let root_p = poseidon_tree_root(&mut poseidon, res_p, &[]);
    let root_k = h256_tree_root(&res_k);
    let root_k = encode_h256_to_field(&root_k);
    vec![root_k[0], root_k[1], root_p, block_num_root_p]
}

fn test_mock_account_queries(
    block_responses: Vec<(Fr, u32)>,
    queries: Vec<(u64, &str)>,
    not_empty: Vec<bool>,
) {
    let params = EthConfigParams::from_path("configs/tests/account_query.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let queries = queries
        .into_iter()
        .map(|(block_number, address)| {
            let address = address.parse().unwrap();
            (block_number, address)
        })
        .collect();

    let input =
        MultiAccountCircuit::from_provider(&setup_provider(), block_responses, queries, not_empty);
    let instance =
        native_account_instance(&input.block_responses, &input.queries, &input.not_empty);
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);

    MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied();
}

#[test]
fn test_mock_account_queries_simple() {
    let queries = vec![
        (17143006, "0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B"),
        (17143000, "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
        (15000000, "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
        (15411056, "0x1c479675ad559DC151F6Ec7ed3FbF8ceE79582B6"),
    ];
    let mut rng = thread_rng();
    let block_responses = queries.iter().map(|_| (Fr::random(OsRng), rng.gen())).collect();
    let not_empty = vec![true; queries.len()];
    test_mock_account_queries(block_responses, queries, not_empty);
}

#[test]
fn test_mock_account_queries_genesis() {
    // address existing in block 0
    let address = "0x756F45E3FA69347A9A973A725E3C98bC4db0b5a0";
    let mut rng = thread_rng();
    let latest = get_latest_block_number();
    let mut queries: Vec<_> = (0..7).map(|_| (rng.gen_range(0..latest), address)).collect();
    queries.push((0, address));
    let block_responses = queries.iter().map(|_| (Fr::random(OsRng), rng.gen())).collect();
    let mut not_empty = vec![true; queries.len()];
    for ne in not_empty.iter_mut().take(queries.len() / 2) {
        *ne = false;
    }
    test_mock_account_queries(block_responses, queries, not_empty);
}

#[test]
fn test_mock_account_queries_empty() {
    let address = "0x0000000000000000000000000000000000000000";
    let mut rng = thread_rng();
    let latest = get_latest_block_number();
    let mut queries: Vec<_> = (0..7).map(|_| (rng.gen_range(0..latest), address)).collect();
    queries.push((0, address));
    let block_responses = queries.iter().map(|_| (Fr::random(OsRng), rng.gen())).collect();
    let not_empty = vec![false; queries.len()];
    test_mock_account_queries(block_responses, queries, not_empty);
}

use super::{setup_provider, setup_provider_goerli};
use crate::{
    batch_query::{
        hash::poseidon_tree_root,
        response::{
            block_header::{
                MultiBlockCircuit, GENESIS_BLOCK, GENESIS_BLOCK_RLP, MMR_MAX_NUM_PEAKS,
            },
            native::get_block_response,
        },
        tests::get_latest_block_number,
    },
    providers::{get_block_rlp, get_blocks},
    rlp::builder::RlcThreadBuilder,
    util::{encode_h256_to_field, h256_tree_root, EthConfigParams},
    EthPreCircuit, Network,
};
use ethers_core::{types::H256, utils::keccak256};
use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use itertools::Itertools;
use rand::Rng;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use snark_verifier::util::hash::Poseidon;
use snark_verifier_sdk::{halo2::POSEIDON_SPEC, NativeLoader};
use std::env::set_var;
use test_log::test;

fn test_mock_block_queries(
    block_numbers: Vec<u64>,
    not_empty: Vec<bool>,
    network: Network,
    expected: bool,
) {
    let params = EthConfigParams::from_path("configs/tests/block_query.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let provider = match network {
        Network::Mainnet => setup_provider(),
        Network::Goerli => setup_provider_goerli(),
    };
    let mmr_len = *block_numbers.iter().max().unwrap_or(&0) as usize + 1;
    let blocks = get_blocks(&provider, block_numbers).unwrap();
    let header_rlps = blocks
        .iter()
        .map(|block| get_block_rlp(block.as_ref().expect("block not found")))
        .collect_vec();
    // this is just to get mmr_bit check to pass, we do not check real mmr in this test
    let mmr = (0..MMR_MAX_NUM_PEAKS)
        .map(|i| H256::from_low_u64_be((mmr_len as u64 >> i) & 1u64))
        .collect_vec();
    let mmr_proofs = vec![vec![]; header_rlps.len()];
    let input =
        MultiBlockCircuit::new(header_rlps, not_empty.clone(), network, mmr, mmr_len, mmr_proofs);
    // instance calculation natively for test validation
    let mut poseidon = Poseidon::from_spec(&NativeLoader, POSEIDON_SPEC.clone());
    let (res_p, res_k): (Vec<_>, Vec<_>) = blocks
        .into_iter()
        .zip_eq(not_empty)
        .map(|(block, not_empty)| {
            let ((mut pos, mut kec), _) =
                get_block_response(&mut poseidon, block.unwrap(), network);
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

    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    let instance = circuit.instance();
    for (a, b) in [root_k[0], root_k[1], root_p].into_iter().zip(instance.iter()) {
        assert_eq!(a, *b);
    }

    if expected {
        MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied();
    }
}

#[test]
fn test_mock_block_queries_random() {
    let len = 32;
    let mut rng = ChaChaRng::from_seed([0u8; 32]);
    let latest = get_latest_block_number();
    let block_numbers = (0..len).map(|_| rng.gen_range(0..latest)).collect_vec();
    // test instance generation but not mock prover since no mmr proof
    test_mock_block_queries(block_numbers.clone(), vec![true; len], Network::Mainnet, false);
    // test circuit but not hash values
    test_mock_block_queries(block_numbers, vec![false; len], Network::Mainnet, true);
}

#[test]
fn test_genesis_block() {
    let block = get_blocks(&setup_provider(), [0]).unwrap().pop().unwrap().unwrap();
    assert_eq!(GENESIS_BLOCK.clone(), block);
    assert_eq!(
        format!("{:?}", H256(keccak256(GENESIS_BLOCK_RLP))),
        "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
    );
}

use std::fs::File;

use axiom_eth::{
    block_header::get_block_header_extra_bytes,
    halo2_base::{
        gates::circuit::CircuitBuilderStage::{self, Keygen, Mock, Prover},
        utils::fs::gen_srs,
    },
    halo2_proofs::{dev::MockProver, plonk::Circuit},
    halo2curves::bn256::Fr,
    rlc::circuit::RlcCircuitParams,
    snark_verifier_sdk::{gen_pk, halo2::gen_snark_shplonk},
    utils::{keccak::decorator::RlcKeccakCircuitParams, DEFAULT_RLC_CACHE_BITS},
};
use ethers_core::types::Chain;
use hex::FromHex;
use itertools::Itertools;
use test_log::test;

use super::header_chain::*;

pub mod chain_instance;
pub mod integration;

fn get_rlc_keccak_params(path: &str) -> RlcKeccakCircuitParams {
    serde_json::from_reader(File::open(path).unwrap()).unwrap()
}

#[allow(dead_code)]
fn get_dummy_rlc_keccak_params(k: usize) -> RlcKeccakCircuitParams {
    let mut rlc = RlcCircuitParams::default();
    rlc.base.k = k;
    rlc.base.lookup_bits = Some(8);
    rlc.base.num_instance_columns = 1;
    RlcKeccakCircuitParams { rlc, keccak_rows_per_round: 20 }
}

fn get_default_goerli_header_chain_circuit(
    stage: CircuitBuilderStage,
    circuit_params: RlcKeccakCircuitParams,
) -> EthBlockHeaderChainCircuit<Fr> {
    let network = Chain::Goerli;
    let max_extra_data_bytes = get_block_header_extra_bytes(network);
    let blocks: Vec<String> =
        serde_json::from_reader(File::open("data/headers/default_blocks_goerli.json").unwrap())
            .unwrap();
    let header_rlp_encodings = blocks.into_iter().map(|s| Vec::from_hex(s).unwrap()).collect_vec();
    let max_depth = 3;

    let input =
        EthBlockHeaderChainInput::new(header_rlp_encodings, 7, max_depth, max_extra_data_bytes);
    EthBlockHeaderChainCircuit::new_impl(stage, input, circuit_params, DEFAULT_RLC_CACHE_BITS)
}

#[test]
pub fn test_multi_goerli_header_mock() {
    // let circuit_params = get_dummy_rlc_keccak_params(k);
    let circuit_params = get_rlc_keccak_params("configs/tests/multi_block.json");
    let k = circuit_params.k() as u32;

    let mut circuit = get_default_goerli_header_chain_circuit(Mock, circuit_params);
    circuit.calculate_params();
    let instances = circuit.instances();
    MockProver::run(k, &circuit, instances).unwrap().assert_satisfied();
    serde_json::to_writer_pretty(
        File::create("configs/tests/multi_block.json").unwrap(),
        &circuit.params(),
    )
    .unwrap();
}

#[test]
pub fn test_header_instances_constrained() {
    let circuit_params = get_rlc_keccak_params("configs/tests/multi_block.json");
    let k = circuit_params.k() as u32;

    let circuit = get_default_goerli_header_chain_circuit(Mock, circuit_params);

    assert!(
        MockProver::run(k, &circuit, vec![vec![]]).unwrap().verify().is_err(),
        "instances were not constrained"
    );
}

#[test]
pub fn test_multi_goerli_header_prover() {
    let circuit_params = get_rlc_keccak_params("configs/tests/multi_block.json");
    let k = circuit_params.k() as u32;

    let mut circuit = get_default_goerli_header_chain_circuit(Keygen, circuit_params);
    circuit.calculate_params();

    let params = gen_srs(k);
    let pk = gen_pk(&params, &circuit, None);
    let circuit_params = circuit.params();
    let break_points = circuit.break_points();
    drop(circuit);

    let circuit = get_default_goerli_header_chain_circuit(Prover, circuit_params)
        .use_break_points(break_points);
    // this does proof verification automatically
    gen_snark_shplonk(&params, &pk, circuit, None::<&str>);
}

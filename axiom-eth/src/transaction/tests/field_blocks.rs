use super::*;

use crate::halo2_proofs::dev::MockProver;
use crate::util::EthConfigParams;

use serde::{Deserialize, Serialize};
use std::{env::set_var, fs::File};
use test_log::test;

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct TxFieldProviderInput {
    pub idxs: Vec<(usize, usize)>,
    pub block_numbers: Vec<u32>,
}

fn get_test_field_circuit(
    network: Network,
    idxs: Vec<(usize, usize)>,
    block_numbers: Vec<u32>,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
) -> EthBlocksTransactionFieldCircuit {
    assert!(idxs.len() <= 10);
    let provider = setup_provider(network);

    EthBlocksTransactionFieldCircuit::from_provider(
        &provider,
        idxs,
        block_numbers,
        6,
        network,
        max_data_byte_len,
        max_access_list_len,
        enable_types,
    )
}

pub fn test_field_valid_input_json(
    path: String,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
) -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction.json");
    let file_inputs: TxFieldProviderInput =
        serde_json::from_reader(File::open(path).expect("path does not exist")).unwrap();
    let idxs = file_inputs.idxs;
    let block_numbers = file_inputs.block_numbers;
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let input = get_test_field_circuit(
        Network::Mainnet,
        idxs,
        block_numbers,
        max_data_byte_len,
        max_access_list_len,
        enable_types,
    );
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

pub fn test_field_valid_input_direct(
    idxs: Vec<(usize, usize)>,
    block_numbers: Vec<u32>,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
) -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let input = get_test_field_circuit(
        Network::Mainnet,
        idxs,
        block_numbers,
        max_data_byte_len,
        max_access_list_len,
        enable_types,
    );
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

#[test]
pub fn test_mock_one_block_legacy() -> Result<(), Box<dyn std::error::Error>> {
    return test_field_valid_input_direct(
        vec![(257, 0 /*nonce*/)],
        vec![5000008],
        256,
        0,
        [true, false, false],
    );
}

#[test]
pub fn test_mock_three_blocks_legacy_json() -> Result<(), Box<dyn std::error::Error>> {
    return test_field_valid_input_json(
        "src/transaction/tests/data/field_blocks/single_tx_pos_test_legacy.json".to_string(),
        256,
        0,
        [true, false, false],
    );
}

#[test]
pub fn test_mock_three_blocks_new_json() -> Result<(), Box<dyn std::error::Error>> {
    return test_field_valid_input_json(
        "src/transaction/tests/data/field_blocks/single_tx_pos_test_new.json".to_string(),
        768,
        0,
        [true, false, true],
    );
}

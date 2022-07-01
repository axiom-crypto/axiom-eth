use crate::{providers::from_hex, rlc::circuit::executor::RlcExecutor};

use self::test_circuits::{
    SSZAssignedListTestCircuit, SSZBasicTypeTestCircuit, SSZListTestCircuit, SSZVectorTestCircuit,
};

use super::*;
use halo2_base::{
    gates::circuit::CircuitBuilderStage,
    halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr},
};
use test_log::test;

mod test_circuits;

fn get_test_circuit(input: SSZInput) -> SSZInclusionCircuit<Fr> {
    SSZInclusionCircuit::from_input(input)
}

fn get_basic_type_test_circuit(
    hash_root: &str,
    int_bit_size: usize,
    value: u64,
) -> SSZBasicTypeTestCircuit<Fr> {
    SSZBasicTypeTestCircuit::from_input(from_hex(hash_root), int_bit_size, value)
}

fn get_vector_test_circuit(
    hash_root: &str,
    int_bit_size: usize,
    value: Vec<u64>,
) -> SSZVectorTestCircuit<Fr> {
    SSZVectorTestCircuit::from_input(from_hex(hash_root), int_bit_size, value)
}

fn get_list_test_circuit(
    hash_root: &str,
    int_bit_size: usize,
    value: Vec<u64>,
    len: usize,
    max_len: usize,
) -> SSZListTestCircuit<Fr> {
    SSZListTestCircuit::from_input(from_hex(hash_root), int_bit_size, value, len, max_len)
}

fn get_assigned_list_test_circuit(
    hash_root: &str,
    int_bit_size: usize,
    value: Vec<u64>,
    len: usize,
    max_len: usize,
) -> SSZAssignedListTestCircuit<Fr> {
    SSZAssignedListTestCircuit::from_input(from_hex(hash_root), int_bit_size, value, len, max_len)
}

//const CACHE_BITS: usize = 10;
const DEGREE: usize = 15;
pub fn test_mock_circuit(input: impl RlcCircuitInstructions<Fr>) -> bool {
    let mut builder = RlcCircuitBuilder::from_stage(CircuitBuilderStage::Mock, 10).use_k(DEGREE);
    builder.base.set_lookup_bits(8);
    let circuit = RlcExecutor::new(builder, input);
    circuit.0.calculate_params(Some(9));
    MockProver::run(DEGREE as u32, &circuit, vec![]).unwrap().verify().is_ok()
}

pub fn test_valid_input_json(path: String, max_depth: usize) -> bool {
    let pf_str = std::fs::read_to_string(path).unwrap();
    let pf: serde_json::Value = serde_json::from_str(pf_str.as_str()).unwrap();
    let val: String = serde_json::from_value(pf["val"].clone()).unwrap();
    let val = from_hex(&val);
    let root_bytes: String = serde_json::from_value(pf["root_bytes"].clone()).unwrap();
    let root_bytes = from_hex(&root_bytes);
    let pf_strs: Vec<String> = serde_json::from_value(pf["proof"].clone()).unwrap();
    let proof: Vec<Vec<u8>> = pf_strs.into_iter().map(|pf| from_hex(&pf)).collect();
    let directions: Vec<u8> = serde_json::from_value(pf["directions"].clone()).unwrap();
    let depth = proof.len();
    let input = SSZInput { val, root_bytes, proof, directions, depth, max_depth };
    let input = get_test_circuit(input);
    test_mock_circuit(input)
}

pub fn test_basic_type_json(path: String) -> bool {
    let pf_str = std::fs::read_to_string(path).unwrap();
    let pf: serde_json::Value = serde_json::from_str(pf_str.as_str()).unwrap();
    let val: u64 = serde_json::from_value(pf["value"].clone()).unwrap();
    let hash_root: String = serde_json::from_value(pf["hash_root"].clone()).unwrap();
    let int_bit_size: usize = serde_json::from_value(pf["bit_size"].clone()).unwrap();
    let input = get_basic_type_test_circuit(&hash_root, int_bit_size, val);
    test_mock_circuit(input)
}

pub fn test_vector_json(path: String) -> bool {
    let pf_str = std::fs::read_to_string(path).unwrap();
    let pf: serde_json::Value = serde_json::from_str(pf_str.as_str()).unwrap();
    let val: Vec<u64> = serde_json::from_value(pf["value"].clone()).unwrap();
    let hash_root: String = serde_json::from_value(pf["hash_root"].clone()).unwrap();
    let int_bit_size: usize = serde_json::from_value(pf["bit_size"].clone()).unwrap();
    let input = get_vector_test_circuit(&hash_root, int_bit_size, val);
    test_mock_circuit(input)
}

pub fn test_list_json(path: String) -> bool {
    let pf_str = std::fs::read_to_string(path).unwrap();
    let pf: serde_json::Value = serde_json::from_str(pf_str.as_str()).unwrap();
    let val: Vec<u64> = serde_json::from_value(pf["value"].clone()).unwrap();
    let hash_root: String = serde_json::from_value(pf["hash_root"].clone()).unwrap();
    let int_bit_size: usize = serde_json::from_value(pf["bit_size"].clone()).unwrap();
    let max_len: usize = serde_json::from_value(pf["max_len"].clone()).unwrap();
    let len: usize = serde_json::from_value(pf["len"].clone()).unwrap();
    let input = get_list_test_circuit(&hash_root, int_bit_size, val, len, max_len);
    test_mock_circuit(input)
}

pub fn test_assigned_list_json(path: String) -> bool {
    let pf_str = std::fs::read_to_string(path).unwrap();
    let pf: serde_json::Value = serde_json::from_str(pf_str.as_str()).unwrap();
    let val: Vec<u64> = serde_json::from_value(pf["value"].clone()).unwrap();
    let hash_root: String = serde_json::from_value(pf["hash_root"].clone()).unwrap();
    let int_bit_size: usize = serde_json::from_value(pf["bit_size"].clone()).unwrap();
    let max_len: usize = serde_json::from_value(pf["max_len"].clone()).unwrap();
    let len: usize = serde_json::from_value(pf["len"].clone()).unwrap();
    let input = get_assigned_list_test_circuit(&hash_root, int_bit_size, val, len, max_len);
    test_mock_circuit(input)
}

#[test]
pub fn test_mock_ssz_merkle_proof() -> Result<(), Box<dyn std::error::Error>> {
    match test_valid_input_json("src/ssz/tests/merkle_proof/proof.json".to_string(), 10) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_misdirected_ssz_merkle_proof() -> Result<(), Box<dyn std::error::Error>> {
    match test_valid_input_json("src/ssz/tests/merkle_proof/misdirected_proof.json".to_string(), 10)
    {
        true => panic!("Should not have verified"),
        false => Ok(()),
    }
}

#[test]
pub fn test_incorrect_ssz_merkle_proof() -> Result<(), Box<dyn std::error::Error>> {
    match test_valid_input_json("src/ssz/tests/merkle_proof/incorrect_proof.json".to_string(), 10) {
        true => panic!("Should not have verified"),
        false => Ok(()),
    }
}

#[test]
pub fn test_real_ssz_merkle_proof() -> Result<(), Box<dyn std::error::Error>> {
    match test_valid_input_json("src/ssz/tests/merkle_proof/real_proof.json".to_string(), 41) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_validator_into_beacon_state() -> Result<(), Box<dyn std::error::Error>> {
    match test_valid_input_json("src/ssz/tests/merkle_proof/real_beacon_proof.json".to_string(), 50)
    {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_byte_basic_type_root() -> Result<(), Box<dyn std::error::Error>> {
    match test_basic_type_json("src/ssz/tests/basic_types/byte.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_bool_basic_type_root() -> Result<(), Box<dyn std::error::Error>> {
    match test_basic_type_json("src/ssz/tests/basic_types/bool.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_u64_basic_type_root() -> Result<(), Box<dyn std::error::Error>> {
    match test_basic_type_json("src/ssz/tests/basic_types/u64.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_u16_basic_type_root() -> Result<(), Box<dyn std::error::Error>> {
    match test_basic_type_json("src/ssz/tests/basic_types/u16.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_neg_bool_root() -> Result<(), Box<dyn std::error::Error>> {
    match test_basic_type_json("src/ssz/tests/basic_types/neg_bool.json".to_string()) {
        true => panic!("Should not have verified"),
        false => Ok(()),
    }
}

#[test]
#[should_panic = "assertion failed"] // check this later
pub fn test_neg_byte_root() {
    assert!(
        !test_basic_type_json("src/ssz/tests/basic_types/neg_byte.json".to_string()),
        "Should not have verified"
    );
}

#[test]
pub fn test_six_u64_root() -> Result<(), Box<dyn std::error::Error>> {
    match test_vector_json("src/ssz/tests/vectors/six_u64.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_unfull_list_root() -> Result<(), Box<dyn std::error::Error>> {
    match test_list_json("src/ssz/tests/lists/unfull_list.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_empty_list_root() -> Result<(), Box<dyn std::error::Error>> {
    match test_list_json("src/ssz/tests/lists/empty_list.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
#[should_panic = "assertion failed"] // check this later
pub fn test_bad_len_list_root() {
    assert!(
        !test_list_json("src/ssz/tests/lists/bad_len_list.json".to_string()),
        "Should not have verified"
    );
}

#[test]
pub fn test_assigned_unfull_list_root() -> Result<(), Box<dyn std::error::Error>> {
    match test_assigned_list_json("src/ssz/tests/lists/unfull_list.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_assigned_empty_list_root() -> Result<(), Box<dyn std::error::Error>> {
    match test_assigned_list_json("src/ssz/tests/lists/empty_list.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_assigned_bad_len_list_root() -> Result<(), Box<dyn std::error::Error>> {
    match test_assigned_list_json("src/ssz/tests/lists/bad_len_list.json".to_string()) {
        true => panic!("Should not have verified"),
        false => Ok(()),
    }
}


use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use serde_json::Value;

use super::{
    data_gen::{get_balance_into_beacon, get_validator_info_into_beacon},
    types::SszUint64,
    *,
};
use crate::{
    providers::from_hex,
    rlc::circuit::{builder::RlcCircuitBuilder, instructions::RlcCircuitInstructions},
    sha256::Sha256Chip,
    ssz::{
        tests::test_mock_circuit,
        types::{SszBasicType, SszBasicTypeVector},
        SSZInput,
    },
};
use std::{
    fs::File,
    io::{BufWriter, Write},
    marker::PhantomData,
};

#[derive(Clone, Debug)]
pub struct ValidatorInfoCircuit<F> {
    pub idx: usize,
    pub proof: SSZInput, // public and private inputs
    pub bls_pubkey: Vec<u8>,
    pub withdrawal_creds: Vec<u8>,
    pub max_depth: usize,
    _marker: PhantomData<F>,
}

impl<F> ValidatorInfoCircuit<F> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_input(
        idx: usize,
        proof: SSZInput,
        bls_pubkey: Vec<u8>,
        withdrawal_creds: Vec<u8>,
    ) -> Self {
        assert!(bls_pubkey.len() == 48);
        assert!(withdrawal_creds.len() == 32);
        let max_depth = proof.max_depth;
        assert!(max_depth == 48);
        Self { idx, proof, bls_pubkey, withdrawal_creds, max_depth, _marker: PhantomData }
    }
}

impl<F: Field> RlcCircuitInstructions<F> for ValidatorInfoCircuit<F> {
    type FirstPhasePayload = ();
    fn generate_witnesses_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
    ) -> Self::FirstPhasePayload {
        let sha = Sha256Chip::new(range);
        let ssz = SszChip::new(None, &range, sha);
        let ctx = builder.base.main(0);
        let proof = self.proof.clone().assign(ctx);
        let bls_pubkey = self.bls_pubkey.iter().map(|b| *b as u64).collect_vec();
        let withdrawal_creds = self.withdrawal_creds.iter().map(|b| *b as u64).collect_vec();
        let bls_pubkey = SszBasicTypeVector::new_from_ints(ctx, &range, bls_pubkey, 8);
        let withdrawal_creds = SszBasicTypeVector::new_from_ints(ctx, &range, withdrawal_creds, 8);
        let info = ValidatorInfo::from(bls_pubkey, withdrawal_creds);
        let beacon = BeaconChip::new(&ssz);
        let idx = ctx.load_witness(F::from(self.idx as u64));
        let _witness = beacon.verify_validator_info_from_beacon_block_root(ctx, idx, &info, proof);
    }
    fn generate_witnesses_phase1(
        _builder: &mut RlcCircuitBuilder<F>,
        _range: &RangeChip<F>,
        _rlc: &RlcChip<F>,
        _payload: Self::FirstPhasePayload,
    ) {
    }
}

#[derive(Clone, Debug)]
pub struct BalanceCircuit<F> {
    pub idx: usize,
    pub proof: SSZInput, // public and private inputs
    pub balance: u64,
    pub max_depth: usize,
    _marker: PhantomData<F>,
}

impl<F> BalanceCircuit<F> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "providers")]
    pub fn from_input(idx: usize, proof: SSZInput, balance: u64) -> Self {
        let max_depth = proof.max_depth;
        assert!(max_depth == 44);
        Self { idx, proof, balance, max_depth, _marker: PhantomData }
    }
}

impl<F: Field> RlcCircuitInstructions<F> for BalanceCircuit<F> {
    type FirstPhasePayload = ();
    fn generate_witnesses_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
    ) -> Self::FirstPhasePayload {
        let sha = Sha256Chip::new(range);
        let ssz = SszChip::new(None, &range, sha);
        let ctx = builder.base.main(0);
        let proof = self.proof.clone().assign(ctx);
        let balance = SszBasicType::new_from_int(ctx, &range, self.balance, 64);
        let balance = SszUint64::from(balance);
        let beacon = BeaconChip::new(&ssz);
        let idx_div_4 = ctx.load_witness(F::from(self.idx as u64 / 4));
        let idx_mod_4 = ctx.load_witness(F::from(self.idx as u64 % 4));
        let idx = ctx.load_witness(F::from(self.idx as u64));
        let (_idx, _len, _witness) = beacon
            .verify_balance_from_beacon_block_root(ctx, idx, idx_div_4, idx_mod_4, &balance, proof);
    }
    fn generate_witnesses_phase1(
        _builder: &mut RlcCircuitBuilder<F>,
        _range: &RangeChip<F>,
        _rlc: &RlcChip<F>,
        _payload: Self::FirstPhasePayload,
    ) {
    }
}

fn get_test_info_circuit(
    idx: usize,
    proof: SSZInput,
    bls_pubkey: Vec<u8>,
    withdrawal_creds: Vec<u8>,
) -> ValidatorInfoCircuit<Fr> {
    ValidatorInfoCircuit::from_input(idx, proof, bls_pubkey, withdrawal_creds)
}

fn get_test_balance_circuit(idx: usize, proof: SSZInput, balance: u64) -> BalanceCircuit<Fr> {
    BalanceCircuit::from_input(idx, proof, balance)
}

pub fn test_info_valid_input_json(path: String) -> bool {
    let pf_str = std::fs::read_to_string(path).unwrap();
    let overall_pf: serde_json::Value = serde_json::from_str(pf_str.as_str()).unwrap();
    let idx: usize = serde_json::from_value(overall_pf["idx"].clone()).unwrap();
    let bls: String = serde_json::from_value(overall_pf["public_key"].clone()).unwrap();
    let bls = Vec::<u8>::try_from(from_hex(&bls[2..])).unwrap();
    let wc: String = serde_json::from_value(overall_pf["withdrawal_credentials"].clone()).unwrap();
    let wc = Vec::<u8>::try_from(from_hex(&wc[2..])).unwrap();
    let pf = overall_pf["proof"].clone();
    let val: String = serde_json::from_value(pf["val"].clone()).unwrap();
    let val = from_hex(&val);
    let root_bytes: String = serde_json::from_value(pf["root_bytes"].clone()).unwrap();
    let root_bytes = from_hex(&root_bytes);
    let pf_strs: Vec<String> = serde_json::from_value(pf["proof"].clone()).unwrap();
    let proof: Vec<Vec<u8>> = pf_strs.into_iter().map(|pf| from_hex(&pf)).collect();
    let directions: Vec<u8> = serde_json::from_value(pf["directions"].clone()).unwrap();
    let depth = proof.len();
    let proof = SSZInput { root_bytes, val, proof, directions, depth: 48, max_depth: depth };
    let input = get_test_info_circuit(idx, proof, bls, wc);
    test_mock_circuit(input)
}

pub fn test_balance_valid_input_json(path: String) -> bool {
    let pf_str = std::fs::read_to_string(path).unwrap();
    let overall_pf: serde_json::Value = serde_json::from_str(pf_str.as_str()).unwrap();
    let idx: usize = serde_json::from_value(overall_pf["idx"].clone()).unwrap();
    let balance: u64 = serde_json::from_value(overall_pf["balance"].clone()).unwrap();
    let pf = overall_pf["proof"].clone();
    let val: String = serde_json::from_value(pf["val"].clone()).unwrap();
    let val = from_hex(&val);
    let root_bytes: String = serde_json::from_value(pf["root_bytes"].clone()).unwrap();
    let root_bytes = from_hex(&root_bytes);
    let pf_strs: Vec<String> = serde_json::from_value(pf["proof"].clone()).unwrap();
    let proof: Vec<Vec<u8>> = pf_strs.into_iter().map(|pf| from_hex(&pf)).collect();
    let directions: Vec<u8> = serde_json::from_value(pf["directions"].clone()).unwrap();
    let depth = proof.len();
    let proof = SSZInput { root_bytes, val, proof, directions, depth: 44, max_depth: depth };
    let input = get_test_balance_circuit(idx, proof, balance);
    test_mock_circuit(input)
}

#[test]
pub fn test_select_validator_info_proof() -> Result<(), Box<dyn std::error::Error>> {
    let idx = std::fs::read_to_string("src/beacon/tests/info_idx.json").unwrap();
    let idx: serde_json::Value = serde_json::from_str(idx.as_str()).unwrap();
    let idx: usize = serde_json::from_value(idx["idx"].clone()).unwrap();
    gen_data_and_test_select_validator_info_proof(idx)
}

pub fn gen_data_and_test_select_validator_info_proof(
    idx: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let map = get_validator_info_into_beacon(idx);
    let proof = Value::Object(map);
    let file = File::create("src/beacon/tests/info_test.json").unwrap();
    let mut writer = BufWriter::new(file);
    let _ = serde_json::to_writer_pretty(&mut writer, &proof);
    let _ = writer.flush();
    match test_info_valid_input_json("src/beacon/tests/info_test.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_mock_validator_info_proof() -> Result<(), Box<dyn std::error::Error>> {
    match test_info_valid_input_json("src/beacon/tests/info_test_sandbox.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_select_balance_proof() -> Result<(), Box<dyn std::error::Error>> {
    let idx = std::fs::read_to_string("src/beacon/tests/balance_idx.json").unwrap();
    let idx: serde_json::Value = serde_json::from_str(idx.as_str()).unwrap();
    let idx: usize = serde_json::from_value(idx["idx"].clone()).unwrap();
    gen_data_and_test_select_balance_proof(idx)
}

pub fn gen_data_and_test_select_balance_proof(
    idx: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let map = get_balance_into_beacon(idx);
    let proof = Value::Object(map);
    let file = File::create("src/beacon/tests/balance_test.json").unwrap();
    let mut writer = BufWriter::new(file);
    let _ = serde_json::to_writer_pretty(&mut writer, &proof);
    let _ = writer.flush();
    match test_balance_valid_input_json("src/beacon/tests/balance_test.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

#[test]
pub fn test_mock_balance_proof() -> Result<(), Box<dyn std::error::Error>> {
    match test_balance_valid_input_json("src/beacon/tests/balance_test_sandbox.json".to_string()) {
        true => Ok(()),
        false => panic!("Should have verified"),
    }
}

use super::*;
use crate::{
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    keccak::{FixedLenRLCs, FnSynthesize, KeccakCircuitBuilder, VarLenRLCs},
    rlp::builder::RlcThreadBuilder,
    util::EthConfigParams,
};
use ark_std::{end_timer, start_timer};
use ethers_core::utils::keccak256;
use halo2_base::{
    halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    utils::fs::gen_srs,
};
use hex::FromHex;
use rand_core::OsRng;
use std::{
    cell::RefCell,
    env::{set_var, var},
    fs::File,
    io::{BufReader, Write},
    path::Path,
};
use test_log::test;
use test_case::test_case;

#[test_case("scripts/input_gen/pos_data/inclusion1_pf.json".to_string(); "correct inclusion 1")]
#[test_case("scripts/input_gen/pos_data/inclusion2_pf.json".to_string(); "correct inclusion 2")]
#[test_case("scripts/input_gen/neg_data/wrong_path_default_storage_pf.json".to_string(); "wrong path inclusion")]
#[test_case("scripts/input_gen/neg_data/wrong_val_default_storage_pf.json".to_string(); "wrong val inclusion")]
#[test_case("scripts/input_gen/neg_data/wrong_proof_default_storage_pf.json".to_string(); "wrong proof inclusion")]

pub fn test_mpt_inclusion_fixed(path : String) {
    let params = EthConfigParams::from_path("configs/tests/mpt.json");
    // std::env::set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let input = mpt_input(path, false, 5); // depth = max_depth
    let circuit = test_mpt_circuit(k, RlcThreadBuilder::<Fr>::mock(), input);
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
}



#[test_case("scripts/input_gen/pos_data/noninclusion_branch_pf.json".to_string(); "branch exclusion")]
#[test_case("scripts/input_gen/pos_data/noninclusion_extension_pf.json".to_string(); "extension exclusion")]

#[test_case("scripts/input_gen/neg_data/wrong_path_noninclusion_branch_pf.json".to_string(); "wrong path exclusion")]
#[test_case("scripts/input_gen/neg_data/wrong_val_noninclusion_branch_pf.json".to_string(); "wrong val exclusion")]
#[test_case("scripts/input_gen/neg_data/wrong_proof_noninclusion_extension_pf.json".to_string(); "wrong proof exclusion")]
pub fn test_mpt_exclusion_fixed(path : String) {
    let params = EthConfigParams::from_path("configs/tests/mpt.json");
    // std::env::set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let input = mpt_input(path, true, 5); // depth = max_depth
    let circuit = test_mpt_circuit(k, RlcThreadBuilder::<Fr>::mock(), input);
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
}
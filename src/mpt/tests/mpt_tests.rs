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

// fn get_test_circuit(network: Network, num_slots: usize) -> EthBlockStorageCircuit {
//     assert!(num_slots <= 10);
//     let infura_id = var("INFURA_ID").expect("INFURA_ID environmental variable not set");
//     let provider_url = match network {
//         Network::Mainnet => format!("{MAINNET_PROVIDER_URL}{infura_id}"),
//         Network::Goerli => format!("{GOERLI_PROVIDER_URL}{infura_id}"),
//     };
//     let provider = Provider::<Http>::try_from(provider_url.as_str())
//         .expect("could not instantiate HTTP Provider");
//     let addr;
//     let block_number;
//     match network {
//         Network::Mainnet => {
//             // cryptopunks
//             addr = "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB".parse::<Address>().unwrap();
//             block_number = 16356350;
//             //block_number = 0xf929e6;
//         }
//         Network::Goerli => {
//             addr = "0xf2d1f94310823fe26cfa9c9b6fd152834b8e7849".parse::<Address>().unwrap();
//             block_number = 0x713d54;
//         }
//     }
//     // For only occupied slots:
//     let slot_nums = vec![0u64, 1u64, 2u64, 3u64, 6u64, 8u64];
//     let mut slots = (0..4)
//         .map(|x| {
//             let mut bytes = [0u8; 64];
//             bytes[31] = x;
//             bytes[63] = 10;
//             H256::from_slice(&keccak256(bytes))
//         })
//         .collect::<Vec<_>>();
//     slots.extend(slot_nums.iter().map(|x| H256::from_low_u64_be(*x)));
//     // let slots: Vec<_> = (0..num_slots).map(|x| H256::from_low_u64_be(x as u64)).collect();
//     slots.truncate(num_slots);
//     EthBlockStorageCircuit::from_provider(&provider, block_number, addr, slots, 8, 8, network)
// }



#[test]
pub fn test_mpt_noninclusion_extension_fixed() {
    let params = EthConfigParams::from_path("configs/tests/mpt.json");
    let k = params.degree;
    let input = mpt_input("scripts/input_gen/noninclusion_extension_pf.json", true, 6); // require depth < max_depth
    let circuit = test_mpt_circuit(k, RlcThreadBuilder::<Fr>::mock(), input);
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
}



//"scripts/input_gen/noninclusion_extension_pf.json"

//#[test_case("scripts/input_gen/noninclusion_extension_pf.json".to_string() => Fr::from(2) ; "add(): 1 + 1 == 2")]

#[test]
pub fn tests_mpt_noninclusion_extension_fixed() {
    let params = EthConfigParams::from_path("configs/tests/mpt.json");
    let k = params.degree;
    let input = mpt_input("scripts/input_gen/noninclusion_extension_pf.json", true, 6); // require depth < max_depth
    let circuit = test_mpt_circuit(k, RlcThreadBuilder::<Fr>::mock(), input);
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
pub fn tests_mpt_noninclusion_extension_fixed2() {
    let params = EthConfigParams::from_path("configs/tests/mpt.json");
    let k = params.degree;
    let input = mpt_input("scripts/input_gen/noninclusion_extension_pf2.json", true, 6); // require depth < max_depth
    let circuit = test_mpt_circuit(k, RlcThreadBuilder::<Fr>::mock(), input);
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
}




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
use std::str::FromStr;

use axiom_eth::{halo2_proofs::halo2curves::bn256::Fr, utils::hilo::HiLo};
use itertools::Itertools;
use lazy_static::lazy_static;

use super::{
    Groth16VerifierComponent, Groth16VerifierComponentInput, Groth16VerifierComponentOutput,
    Groth16VerifierComponentParams, Groth16VerifierComponentProof,
    Groth16VerifierComponentVerificationKey,
};
use crate::{
    groth16::{vec_to_hilo_pair, vec_to_hilo_point, HiLoPair, HiLoPoint},
    utils::{
        flatten::{FixLenVec, VecKey},
        testing::{basic_component_outputs_test, basic_component_test_prove},
    },
};

macro_rules! deserialize_key {
    ($json: expr, $val: expr) => {
        serde_json::from_value($json[$val].clone()).unwrap()
    };
}

const MAX_PUBLIC_INPUTS: usize = 11;

pub fn read_input(
    vk_file: String,
    pf_file: String,
    pub_file: String,
) -> Groth16VerifierComponentInput<Fr, MAX_PUBLIC_INPUTS> {
    let verification_key_file = std::fs::read_to_string(vk_file).unwrap();
    let verification_key_file: serde_json::Value =
        serde_json::from_str(verification_key_file.as_str()).unwrap();

    let vk_alpha_1: [String; 3] = deserialize_key!(verification_key_file, "vk_alpha_1");
    let vk_beta_2: [[String; 2]; 3] = deserialize_key!(verification_key_file, "vk_beta_2");
    let vk_gamma_2: [[String; 2]; 3] = deserialize_key!(verification_key_file, "vk_gamma_2");
    let vk_delta_2: [[String; 2]; 3] = deserialize_key!(verification_key_file, "vk_delta_2");

    let alpha_g1: HiLoPoint<Fr> = vec_to_hilo_point(&vk_alpha_1);
    let beta_g2: HiLoPair<Fr> = vec_to_hilo_pair(&vk_beta_2);
    let gamma_g2: HiLoPair<Fr> = vec_to_hilo_pair(&vk_gamma_2);
    let delta_g2: HiLoPair<Fr> = vec_to_hilo_pair(&vk_delta_2);

    let ic: Vec<[String; 3]> = deserialize_key!(verification_key_file, "IC");
    let mut ic_vec = ic.into_iter().map(|s| vec_to_hilo_point(&s)).collect_vec();
    ic_vec.resize(MAX_PUBLIC_INPUTS + 1, (HiLo::default(), HiLo::default()));
    let gamma_abc_g1 = VecKey::new(ic_vec).unwrap();

    let vk = Groth16VerifierComponentVerificationKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    };

    let proof_file = std::fs::read_to_string(pf_file).unwrap();
    let proof_file: serde_json::Value = serde_json::from_str(proof_file.as_str()).unwrap();

    // get proof
    let a: [String; 3] = deserialize_key!(proof_file, "pi_a");
    let b: [[String; 2]; 3] = deserialize_key!(proof_file, "pi_b");
    let c: [String; 3] = deserialize_key!(proof_file, "pi_c");

    let a: HiLoPoint<Fr> = vec_to_hilo_point(&a);
    let b: HiLoPair<Fr> = vec_to_hilo_pair(&b);
    let c: HiLoPoint<Fr> = vec_to_hilo_point(&c);

    let pf = Groth16VerifierComponentProof { a, b, c };

    // get public inputs
    let public_file = std::fs::read_to_string(pub_file).unwrap();
    let public_file: serde_json::Value = serde_json::from_str(public_file.as_str()).unwrap();
    let pi: Vec<String> = serde_json::from_value(public_file.clone()).unwrap();
    let len = pi.len();
    let mut pi = pi
        .into_iter()
        .map(|p| Fr::from(u64::from_str(&p).unwrap()))
        .collect_vec();
    pi.resize(MAX_PUBLIC_INPUTS, Fr::from(0));
    let public_inputs = FixLenVec::new(pi).unwrap();

    Groth16VerifierComponentInput {
        vk,
        proof: pf,
        public_inputs,
        num_public_inputs: Fr::from(len as u64 + 1),
    }
}

fn get_groth16_output(success: bool) -> Groth16VerifierComponentOutput<Fr, MAX_PUBLIC_INPUTS> {
    Groth16VerifierComponentOutput {
        success: if success { Fr::one() } else { Fr::zero() },
    }
}

lazy_static! {
    static ref GROTH16VERIFY_PARAMS: Groth16VerifierComponentParams =
        Groth16VerifierComponentParams {
            capacity: 1,
            limb_bits: 88,
            num_limbs: 3,
        };
}

lazy_static! {
    static ref GROTH16VERIFY_PARAMS_CAP2: Groth16VerifierComponentParams =
        Groth16VerifierComponentParams {
            capacity: 2,
            limb_bits: 88,
            num_limbs: 3,
        };
}

#[test]
fn test_groth16_output() {
    basic_component_outputs_test::<Groth16VerifierComponent<Fr, MAX_PUBLIC_INPUTS>>(
        20,
        vec![read_input(
            "src/groth16/test_data/puzzle.json".to_string(),
            "src/groth16/test_data/proof.json".to_string(),
            "src/groth16/test_data/public_inputs.json".to_string(),
        )],
        vec![get_groth16_output(true)],
        GROTH16VERIFY_PARAMS.clone(),
    );
}

#[test]
fn test_groth16_output_default() {
    basic_component_outputs_test::<Groth16VerifierComponent<Fr, MAX_PUBLIC_INPUTS>>(
        20,
        vec![read_input(
            "src/groth16/test_data/default.json".to_string(),
            "src/groth16/test_data/default_proof.json".to_string(),
            "src/groth16/test_data/default_public_inputs.json".to_string(),
        )],
        vec![get_groth16_output(true)],
        GROTH16VERIFY_PARAMS.clone(),
    );
}

#[test]
fn test_groth16_output_with_wrong_signature() {
    basic_component_outputs_test::<Groth16VerifierComponent<Fr, MAX_PUBLIC_INPUTS>>(
        20,
        vec![read_input(
            "src/groth16/test_data/puzzle_modified.json".to_string(),
            "src/groth16/test_data/proof.json".to_string(),
            "src/groth16/test_data/public_inputs_modified.json".to_string(),
        )],
        vec![get_groth16_output(false)],
        GROTH16VERIFY_PARAMS.clone(),
    );
}

#[test]
fn test_groth16_prove() {
    basic_component_test_prove::<Groth16VerifierComponent<Fr, MAX_PUBLIC_INPUTS>>(
        20,
        vec![read_input(
            "src/groth16/test_data/puzzle.json".to_string(),
            "src/groth16/test_data/proof.json".to_string(),
            "src/groth16/test_data/public_inputs.json".to_string(),
        )],
        GROTH16VERIFY_PARAMS.clone(),
    )
    .unwrap();
}

#[test]
fn test_groth16_prove_default() {
    basic_component_test_prove::<Groth16VerifierComponent<Fr, MAX_PUBLIC_INPUTS>>(
        20,
        vec![read_input(
            "src/groth16/test_data/default.json".to_string(),
            "src/groth16/test_data/default_proof.json".to_string(),
            "src/groth16/test_data/default_public_inputs.json".to_string(),
        )],
        GROTH16VERIFY_PARAMS.clone(),
    )
    .unwrap();
}

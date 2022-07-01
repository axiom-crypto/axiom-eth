use axiom_eth::{halo2curves::bn256::Fr, utils::hilo::HiLo};
use lazy_static::lazy_static;

use super::{
    utils::{testing::custom_parameters_ecdsa, verify_signature},
    ECDSAComponent, ECDSAComponentInput, ECDSAComponentNativeInput, ECDSAComponentOutput,
    ECDSAComponentParams,
};
use crate::utils::testing::{
    basic_component_outputs_test, basic_component_test_prove, fix_len_logical_input_test,
};

#[test]
fn test_ecdsa_input_flatten() {
    fix_len_logical_input_test(
        ECDSAComponentInput {
            pubkey: (HiLo::from_hi_lo([1, 2]), HiLo::from_hi_lo([3, 4])),
            r: HiLo::from_hi_lo([5, 6]),
            s: HiLo::from_hi_lo([7, 8]),
            msg_hash: HiLo::from_hi_lo([9, 10]),
        },
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    );
}

fn get_ecdsa_output(success: bool) -> ECDSAComponentOutput<Fr> {
    ECDSAComponentOutput {
        success: if success {
            HiLo::from_hi_lo([Fr::zero(), Fr::one()])
        } else {
            HiLo::from_hi_lo([Fr::zero(), Fr::zero()])
        },
    }
}

lazy_static! {
    static ref ECDSA_PARAMS: ECDSAComponentParams = ECDSAComponentParams {
        capacity: 2,
        limb_bits: 88,
        num_limbs: 3,
    };
}

#[test]
fn test_ecdsa_output() {
    basic_component_outputs_test::<ECDSAComponent<Fr>>(
        15,
        vec![
            custom_parameters_ecdsa(1, 1, 1),
            custom_parameters_ecdsa(2, 2, 2),
        ],
        vec![get_ecdsa_output(true), get_ecdsa_output(true)],
        ECDSA_PARAMS.clone(),
    );
}

#[test]
fn test_native_ecdsa_verification() {
    let input = custom_parameters_ecdsa(1, 1, 1);
    let native_input = ECDSAComponentNativeInput::from(input.clone());
    assert!(verify_signature(native_input).unwrap());
}

#[test]
fn test_native_ecdsa_verification_fail() {
    let mut input = custom_parameters_ecdsa(1, 1, 1);
    let second = custom_parameters_ecdsa(2, 2, 2);
    input.s = second.s;
    input.r = second.r;
    let native_input = ECDSAComponentNativeInput::from(input.clone());
    assert!(!verify_signature(native_input).unwrap());
}

#[test]
fn test_ecdsa_output_with_wrong_signature() {
    let mut input = custom_parameters_ecdsa(1, 1, 1);
    //change the signature so the verification should fail
    input.s = HiLo::from_hi_lo([Fr::from(2), Fr::from(2)]);
    basic_component_outputs_test::<ECDSAComponent<Fr>>(
        15,
        vec![custom_parameters_ecdsa(1, 1, 1), input],
        vec![get_ecdsa_output(true), get_ecdsa_output(false)],
        ECDSA_PARAMS.clone(),
    );
}

#[test]
fn test_ecdsa_prove() {
    basic_component_test_prove::<ECDSAComponent<Fr>>(
        15,
        vec![
            custom_parameters_ecdsa(1, 1, 1),
            custom_parameters_ecdsa(2, 2, 2),
        ],
        ECDSA_PARAMS.clone(),
    )
    .unwrap();
}

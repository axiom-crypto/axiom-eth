use axiom_eth::{halo2curves::bn256::Fr, rlc::circuit::RlcCircuitParams};
use halo2_ecc::halo2_base::gates::circuit::BaseCircuitParams;
use lazy_static::lazy_static;

use super::{
    GenericComponent, GenericComponentInput, GenericComponentOutput, GenericComponentParams,
};
use crate::utils::{
    flatten::FixLenVec,
    testing::{
        basic_component_outputs_test, basic_component_test_prove, fix_len_logical_input_test,
    },
};

#[test]
fn test_generic_input_flatten() {
    let input: GenericComponentInput<i32, 2, 3> = GenericComponentInput {
        a: FixLenVec::new(vec![1, 2]).unwrap(),
        b: FixLenVec::new(vec![3, 4, 5]).unwrap(),
    };
    fix_len_logical_input_test(input, vec![1, 2, 3, 4, 5]);
}

lazy_static! {
    static ref GENERIC_INPUT: Vec<GenericComponentInput<Fr, 2, 3>> = vec![
        GenericComponentInput {
            a: FixLenVec::new(vec![Fr::from(1), Fr::from(2)]).unwrap(),
            b: FixLenVec::new(vec![Fr::from(3), Fr::from(4), Fr::from(5)]).unwrap(),
        },
        GenericComponentInput {
            a: FixLenVec::new(vec![Fr::from(6), Fr::from(7)]).unwrap(),
            b: FixLenVec::new(vec![Fr::from(8), Fr::from(9), Fr::from(10)]).unwrap(),
        },
    ];
    static ref GENERIC_OUTPUT: Vec<GenericComponentOutput<Fr, 2, 3>> = vec![
        GenericComponentOutput { sum: Fr::from(15) },
        GenericComponentOutput { sum: Fr::from(40) },
    ];
    static ref GENERIC_PARAMS: GenericComponentParams = GenericComponentParams { capacity: 2 };
    static ref GENERIC_RLC_CIRCUIT_PARAMS: RlcCircuitParams = RlcCircuitParams {
        base: BaseCircuitParams {
            k: 15,
            num_advice_per_phase: vec![20, 0],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![3, 0],
            lookup_bits: Some(14),
            num_instance_columns: 1,
        },
        num_rlc_columns: 0,
    };
}

#[test]
fn test_component_outputs() {
    basic_component_outputs_test::<GenericComponent<Fr, 2, 3>>(
        15,
        GENERIC_INPUT.clone(),
        GENERIC_OUTPUT.clone(),
        GENERIC_PARAMS.clone(),
    )
}

#[test]
fn test_prove() {
    basic_component_test_prove::<GenericComponent<Fr, 2, 3>>(
        15,
        GENERIC_INPUT.clone(),
        GENERIC_PARAMS.clone(),
    )
    .unwrap()
}

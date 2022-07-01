use axiom_eth::{halo2curves::bn256::Fr, rlc::circuit::RlcCircuitParams};
use halo2_ecc::halo2_base::gates::circuit::BaseCircuitParams;
use lazy_static::lazy_static;

use super::{ExampleComponent, ExampleComponentInput, ExampleComponentOutput};
use crate::{
    example::ExampleComponentParams,
    utils::testing::{
        basic_component_outputs_test, basic_component_test_prove, fix_len_logical_input_test,
        get_type_id,
    },
};

#[test]
fn test_example_input_flatten() {
    fix_len_logical_input_test(ExampleComponentInput { a: 1, b: 2 }, vec![1, 2]);
}

lazy_static! {
    static ref EXAMPLE_INPUT: Vec<ExampleComponentInput<Fr>> = vec![
        ExampleComponentInput {
            a: Fr::from(1),
            b: Fr::from(2),
        },
        ExampleComponentInput {
            a: Fr::from(3),
            b: Fr::from(4),
        },
        ExampleComponentInput {
            a: Fr::from(5),
            b: Fr::from(6),
        },
    ];
    static ref EXAMPLE_OUTPUT: Vec<ExampleComponentOutput<Fr>> = vec![
        ExampleComponentOutput { sum: Fr::from(3) },
        ExampleComponentOutput { sum: Fr::from(7) },
        ExampleComponentOutput { sum: Fr::from(11) }
    ];
    static ref EXAMPLE_PARAMS: ExampleComponentParams = ExampleComponentParams { capacity: 3 };
    static ref EXAMPLE_RLC_CIRCUIT_PARAMS: RlcCircuitParams = RlcCircuitParams {
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
    basic_component_outputs_test::<ExampleComponent<Fr>>(
        15,
        EXAMPLE_INPUT.clone(),
        EXAMPLE_OUTPUT.clone(),
        EXAMPLE_PARAMS.clone(),
    )
}

#[test]
fn test_prove() {
    basic_component_test_prove::<ExampleComponent<Fr>>(
        15,
        EXAMPLE_INPUT.clone(),
        EXAMPLE_PARAMS.clone(),
    )
    .unwrap()
}

#[test]
fn test_component_id() {
    assert_eq!(
        get_type_id::<ExampleComponent<Fr>>(),
        "axiom_components::example::ExampleComponent".to_string()
    );
}

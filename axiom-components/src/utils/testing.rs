use ark_std::{end_timer, start_timer};
use axiom_eth::{
    halo2_base::{
        gates::circuit::BaseCircuitParams,
        utils::{
            fs::gen_srs,
            testing::{check_proof_with_instances, gen_proof_with_instances},
        },
    },
    halo2_proofs::plonk::{keygen_pk, keygen_vk},
    halo2curves::bn256::Fr,
    rlc::circuit::RlcCircuitParams,
    utils::{
        build_utils::{dummy::DummyFrom, pinning::CircuitPinningInstructions},
        component::{
            circuit::ComponentCircuitImpl, promise_loader::empty::EmptyPromiseLoader,
            types::FixLenLogical, ComponentCircuit, ComponentType, LogicalInputValue,
            LogicalResult, SelectedDataShardsInMerkle,
        },
    },
    Field,
};

use super::flatten::InputFlatten;
use crate::scaffold::{BasicComponentScaffold, BasicComponentScaffoldImpl};

/// Test that an `InputFlatten` implementation is correct.
/// Checks that `flatten_vec` and `unflatten` are inverses of each other.
pub fn generic_test_flatten<T: InputFlatten<i32> + std::cmp::PartialEq + std::fmt::Debug>(
    input: T,
    expected: Vec<i32>,
) {
    let flattened = input.flatten_vec();
    let unflattened = <T as InputFlatten<i32>>::unflatten(flattened.clone()).unwrap();
    assert_eq!(flattened.clone(), expected);
    assert_eq!(unflattened, input);
    assert_eq!(<T as InputFlatten<i32>>::NUM_FE, expected.len());
}

/// Test that a FixLenLogical implementation is correct.
/// Checks that for a struct `T` that implements `InputFlatten<T>`,
/// `into_raw` and `try_from_raw` are inverses of each other.
pub fn fix_len_logical_input_test<
    T: FixLenLogical<i32> + InputFlatten<i32> + std::cmp::PartialEq + std::fmt::Debug,
>(
    input: T,
    expected: Vec<i32>,
) {
    let flattened = input.clone().into_raw();
    let unflattened = T::try_from_raw(flattened.clone()).unwrap();
    assert_eq!(unflattened, input);
    assert_eq!(flattened, expected);
}

/// Returns a vector of `LogicalResult`s from a vector of inputs and outputs.
pub fn logical_result_from_io<F: Field, T: ComponentType<F>>(
    input: Vec<T::LogicalInput>,
    output: Vec<T::OutputValue>,
) -> Vec<LogicalResult<F, T>> {
    input
        .into_iter()
        .zip(output)
        .map(|(input, output)| LogicalResult::<F, T>::new(input, output))
        .collect()
}

/// Test that the outputs of some `BasicComponentScaffold` component are correct,
/// given some inputs and an expected output.
pub fn basic_component_outputs_test<I: BasicComponentScaffold<Fr> + 'static>(
    k: usize,
    input: Vec<<BasicComponentScaffoldImpl<Fr, I> as ComponentType<Fr>>::LogicalInput>,
    expected_output: Vec<<BasicComponentScaffoldImpl<Fr, I> as ComponentType<Fr>>::OutputValue>,
    component_params: I::Params,
) where
    I::Input<Fr>: LogicalInputValue<Fr> + DummyFrom<I::Params>,
    Vec<I::Input<Fr>>: DummyFrom<I::Params>,
{
    let rlc_circuit_params = RlcCircuitParams {
        base: BaseCircuitParams {
            k,
            lookup_bits: Some(k - 1),
            num_instance_columns: 1,
            ..Default::default()
        },
        num_rlc_columns: 0,
    };

    let mut circuit = ComponentCircuitImpl::<
        Fr,
        BasicComponentScaffoldImpl<Fr, I>,
        EmptyPromiseLoader<Fr>,
    >::new(component_params, (), rlc_circuit_params);
    circuit.feed_input(Box::new(input.clone())).unwrap();
    circuit.calculate_params();
    let output = circuit.compute_outputs().unwrap();
    let logical_result: Vec<LogicalResult<Fr, BasicComponentScaffoldImpl<Fr, I>>> =
        logical_result_from_io(input.clone(), expected_output.clone());
    let expected_output_shard = SelectedDataShardsInMerkle::from_single_shard(logical_result);
    assert_eq!(output, expected_output_shard);
}

/// Test that a `BasicComponentScaffold` component can be proven.
pub fn basic_component_test_prove<I: BasicComponentScaffold<Fr> + 'static>(
    k: usize,
    input: Vec<<BasicComponentScaffoldImpl<Fr, I> as ComponentType<Fr>>::LogicalInput>,
    component_params: <I as BasicComponentScaffold<Fr>>::Params,
) -> anyhow::Result<()>
where
    I::Input<Fr>: LogicalInputValue<Fr> + DummyFrom<I::Params>,
    Vec<I::Input<Fr>>: DummyFrom<I::Params>,
{
    let rlc_circuit_params = RlcCircuitParams {
        base: BaseCircuitParams {
            k,
            lookup_bits: Some(k - 1),
            num_instance_columns: 1,
            ..Default::default()
        },
        num_rlc_columns: 0,
    };

    let mut circuit = ComponentCircuitImpl::<
        Fr,
        BasicComponentScaffoldImpl<Fr, I>,
        EmptyPromiseLoader<Fr>,
    >::new(component_params.clone(), (), rlc_circuit_params.clone());
    circuit.feed_input(Box::new(input.clone())).unwrap();
    circuit.calculate_params();

    let params = gen_srs(rlc_circuit_params.base.k as u32);
    let vk_time = start_timer!(|| "vk gen");
    let vk = keygen_vk(&params, &circuit).unwrap();
    end_timer!(vk_time);
    let pk_time = start_timer!(|| "pk gen");
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    end_timer!(pk_time);

    let pinning = circuit.pinning();
    circuit =
        ComponentCircuitImpl::<Fr, BasicComponentScaffoldImpl<Fr, I>, EmptyPromiseLoader<Fr>>::new(
            component_params,
            (),
            pinning.params.clone(),
        )
        .use_break_points(pinning.break_points);
    circuit.feed_input(Box::new(input))?;

    let pf_time = start_timer!(|| "proof gen");
    let instances: Vec<Fr> = circuit.get_public_instances().into();

    let proof = gen_proof_with_instances(&params, &pk, circuit, &[&instances]);
    end_timer!(pf_time);

    let verify_time = start_timer!(|| "verify");
    check_proof_with_instances(&params, pk.get_vk(), &proof, &[&instances], true);
    end_timer!(verify_time);

    Ok(())
}

pub fn get_type_id<I: BasicComponentScaffold<Fr> + 'static>() -> String
where
    I::Input<Fr>: LogicalInputValue<Fr> + DummyFrom<I::Params>,
{
    BasicComponentScaffoldImpl::<Fr, I>::get_type_id()
}

use anyhow::Ok;
use ark_std::{end_timer, start_timer};

use crate::{
    rlc::circuit::RlcCircuitParams,
    utils::{
        build_utils::pinning::CircuitPinningInstructions,
        component::{
            circuit::CoreBuilderOutputParams,
            promise_loader::comp_loader::SingleComponentLoaderParams,
        },
    },
};
use halo2_base::{
    gates::circuit::BaseCircuitParams,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr},
        plonk::{keygen_pk, keygen_vk},
        poly::kzg::commitment::ParamsKZG,
    },
    utils::testing::{check_proof_with_instances, gen_proof_with_instances},
};
use lazy_static::lazy_static;
use rand_core::OsRng;

use super::{
    circuit::ComponentCircuitImpl,
    promise_loader::single::{PromiseLoader, PromiseLoaderParams},
    *,
};

pub mod collector;
/// Dummy components for testing.
pub mod dummy_comp;
pub mod sum_comp;
use dummy_comp::*;

type CompCircuit =
    ComponentCircuitImpl<Fr, BuilderAddMul<Fr>, PromiseLoader<Fr, ComponentTypeAdd<Fr>>>;

fn build_dummy_component_circuit(
    k: usize,
    comp_loader_params: SingleComponentLoaderParams,
    add_mul_cap: usize,
    input: CoreInputAddMul<Fr>,
    promise_results: &GroupedPromiseResults<Fr>,
) -> anyhow::Result<CompCircuit> {
    let prompt_rlc_params = RlcCircuitParams {
        base: BaseCircuitParams {
            k,
            lookup_bits: Some(8),
            num_instance_columns: 1,
            ..Default::default()
        },
        num_rlc_columns: 1,
    };
    let component_circuit: CompCircuit = ComponentCircuitImpl::new(
        CoreBuilderOutputParams::new(vec![add_mul_cap]),
        PromiseLoaderParams { comp_loader_params: comp_loader_params.clone() },
        prompt_rlc_params,
    );
    component_circuit.feed_input(Box::new(input.clone()))?;
    component_circuit.fulfill_promise_results(promise_results)?;
    Ok(component_circuit)
}

fn prover_test_dummy_component(
    comp_loader_params: SingleComponentLoaderParams,
    add_mul_cap: usize,
    input: CoreInputAddMul<Fr>,
    promise_results: GroupedPromiseResults<Fr>,
) -> anyhow::Result<()> {
    let k = 16;
    let mut component_circuit = build_dummy_component_circuit(
        k,
        comp_loader_params.clone(),
        add_mul_cap,
        input.clone(),
        &promise_results,
    )?;
    component_circuit.calculate_params();

    let mut rng = OsRng;
    let params = ParamsKZG::<Bn256>::setup(k as u32, &mut rng);
    let vk_time = start_timer!(|| "vk gen");
    let vk = keygen_vk(&params, &component_circuit).unwrap();
    end_timer!(vk_time);
    let pk_time = start_timer!(|| "pk gen");
    let pk = keygen_pk(&params, vk, &component_circuit).unwrap();
    end_timer!(pk_time);

    // Reconstruct the circuit from pinning.
    let pinning = component_circuit.pinning();
    component_circuit = CompCircuit::new(
        CoreBuilderOutputParams::new(vec![add_mul_cap]),
        PromiseLoaderParams { comp_loader_params: comp_loader_params.clone() },
        pinning.params.clone(),
    )
    .use_break_points(pinning.break_points);
    component_circuit.feed_input(Box::new(input))?;
    component_circuit.fulfill_promise_results(&promise_results)?;

    let pf_time = start_timer!(|| "proof gen");
    let instances: Vec<Fr> = component_circuit.get_public_instances().into();

    let proof = gen_proof_with_instances(&params, &pk, component_circuit, &[&instances]);
    end_timer!(pf_time);

    let verify_time = start_timer!(|| "verify");
    check_proof_with_instances(&params, pk.get_vk(), &proof, &[&instances], true);
    end_timer!(verify_time);

    Ok(())
}

lazy_static! {
    static ref ADD_MUL_INPUT: CoreInputAddMul<Fr> = CoreInputAddMul::<Fr> {
        inputs: vec![
            LogicalInputAddMul::<Fr> { a: Fr::from(1u64), b: Fr::from(2u64), c: Fr::from(3u64) },
            LogicalInputAddMul::<Fr> { a: Fr::from(4u64), b: Fr::from(5u64), c: Fr::from(6u64) },
        ]
    };
    static ref ADD_MUL_RESULT: Vec<LogicalResult<Fr, ComponentTypeAddMul<Fr>>> = vec![
        LogicalResult::<Fr, ComponentTypeAddMul<Fr>>::new(
            LogicalInputAddMul::<Fr> { a: Fr::from(1u64), b: Fr::from(2u64), c: Fr::from(3u64) },
            LogicalOutputAddMul::<Fr> { c: Fr::from(5u64) },
        ),
        LogicalResult::<Fr, ComponentTypeAddMul<Fr>>::new(
            LogicalInputAddMul::<Fr> { a: Fr::from(4u64), b: Fr::from(5u64), c: Fr::from(6u64) },
            LogicalOutputAddMul::<Fr> { c: Fr::from(26u64) },
        )
    ];
    static ref ADD_RESULT_SHARD1: Vec<LogicalResult<Fr, ComponentTypeAdd<Fr>>> =
        vec![LogicalResult::<Fr, ComponentTypeAdd<Fr>>::new(
            LogicalInputAdd { a: Fr::from(7u64), b: Fr::from(8u64) },
            LogicalOutputAdd::<Fr> { c: Fr::from(15u64) },
        )];
    static ref ADD_RESULT_SHARD2: Vec<LogicalResult<Fr, ComponentTypeAdd<Fr>>> = vec![
        LogicalResult::<Fr, ComponentTypeAdd<Fr>>::new(
            LogicalInputAdd { a: Fr::from(2u64), b: Fr::from(3u64) },
            LogicalOutputAdd::<Fr> { c: Fr::from(5u64) },
        ),
        LogicalResult::<Fr, ComponentTypeAdd<Fr>>::new(
            LogicalInputAdd { a: Fr::from(20u64), b: Fr::from(6u64) },
            LogicalOutputAdd::<Fr> { c: Fr::from(26u64) },
        ),
    ];
}

/// Helper function to create ComponentPromiseResults from multiple shards.
pub fn from_multi_shards<F: Field, T: ComponentType<F>>(
    lrs: Vec<Vec<LogicalResult<F, T>>>,
    selected_shards: Vec<usize>,
) -> ComponentPromiseResultsInMerkle<F> {
    let result_per_shard =
        lrs.into_iter().map(ComponentPromiseResultsInMerkle::<F>::from_single_shard).collect_vec();
    let leaves = result_per_shard.iter().map(|r| r.leaves[0].clone()).collect_vec();
    ComponentPromiseResultsInMerkle::<F>::new(
        leaves,
        selected_shards
            .into_iter()
            .map(|idx| (idx, result_per_shard[idx].shards()[0].1.clone()))
            .collect_vec(),
    )
}

#[test]
fn test_input_height2_read1() -> anyhow::Result<()> {
    // Read 1 shard from a merkle tree with height <= 2.
    let comp_loader_params = SingleComponentLoaderParams::new(2, vec![2]);
    let input = ADD_MUL_INPUT.clone();
    // mock add component.
    let add_results_shard1 = ADD_RESULT_SHARD1.clone();
    let add_results_shard2 = ADD_RESULT_SHARD2.clone();
    let mut promise_results = HashMap::new();
    promise_results.insert(
        ComponentTypeAdd::<Fr>::get_type_id(),
        from_multi_shards(vec![add_results_shard1, add_results_shard2], vec![1]),
    );
    prover_test_dummy_component(comp_loader_params, input.inputs.len(), input, promise_results)
}

#[test]
fn test_input_height2_read2() -> anyhow::Result<()> {
    // Read 2 shard from a merkle tree with height <= 2.
    let comp_loader_params = SingleComponentLoaderParams::new(2, vec![1, 2]);
    let input = ADD_MUL_INPUT.clone();
    // mock add component.
    let add_results_shard1 = ADD_RESULT_SHARD1.clone();
    let add_results_shard2 = ADD_RESULT_SHARD2.clone();
    let mut promise_results = HashMap::new();
    promise_results.insert(
        ComponentTypeAdd::<Fr>::get_type_id(),
        from_multi_shards(vec![add_results_shard1, add_results_shard2], vec![0, 1]),
    );
    prover_test_dummy_component(comp_loader_params, input.inputs.len(), input, promise_results)
}

#[test]
fn test_input_height2_read_1shard_twice() -> anyhow::Result<()> {
    // Read 2 shards from a merkle tree with height <= 2.
    let comp_loader_params = SingleComponentLoaderParams::new(2, vec![2, 2]);
    let input = ADD_MUL_INPUT.clone();
    // mock add component.
    let add_results_shard1 = ADD_RESULT_SHARD1.clone();
    let add_results_shard2 = ADD_RESULT_SHARD2.clone();
    let mut promise_results = HashMap::new();
    promise_results.insert(
        ComponentTypeAdd::<Fr>::get_type_id(),
        // Read shard 0 twice.
        from_multi_shards(vec![add_results_shard1, add_results_shard2], vec![1, 1]),
    );
    prover_test_dummy_component(comp_loader_params, input.inputs.len(), input, promise_results)
}

#[test]
fn test_input_height0_read1() -> anyhow::Result<()> {
    // Read 1 shard from a merkle tree with height = 0.
    let comp_loader_params = SingleComponentLoaderParams::new(0, vec![2]);
    let input = ADD_MUL_INPUT.clone();
    // mock add component.
    let add_results_shard2 = ADD_RESULT_SHARD2.clone();
    let mut promise_results = HashMap::new();
    promise_results.insert(
        ComponentTypeAdd::<Fr>::get_type_id(),
        from_multi_shards(vec![add_results_shard2], vec![0]),
    );
    prover_test_dummy_component(comp_loader_params, input.inputs.len(), input, promise_results)
}

#[test]
#[should_panic]
fn test_input_height2_missing_result() {
    // Read 1 shard with cap=1 from a merkle tree with height <= 2.
    let comp_loader_params = SingleComponentLoaderParams::new(2, vec![1]);
    let input = ADD_MUL_INPUT.clone();
    // mock add component.
    let add_results_shard1 = ADD_RESULT_SHARD1.clone();
    let add_results_shard2 = ADD_RESULT_SHARD2.clone();
    let mut promise_results = HashMap::new();
    promise_results.insert(
        ComponentTypeAdd::<Fr>::get_type_id(),
        from_multi_shards(
            vec![add_results_shard1, add_results_shard2],
            // Shard 0 doesn't have all the promise results, so it should panic.
            vec![0],
        ),
    );
    prover_test_dummy_component(comp_loader_params, input.inputs.len(), input, promise_results)
        .unwrap();
}

#[test]
fn test_compute_outputs() -> anyhow::Result<()> {
    // Read 1 shard from a merkle tree with height <= 2.
    let comp_loader_params = SingleComponentLoaderParams::new(2, vec![2]);
    let input = ADD_MUL_INPUT.clone();
    // mock add component.
    let add_results_shard1 = ADD_RESULT_SHARD1.clone();
    let add_results_shard2 = ADD_RESULT_SHARD2.clone();
    let mut promise_results = HashMap::new();
    promise_results.insert(
        ComponentTypeAdd::<Fr>::get_type_id(),
        from_multi_shards(vec![add_results_shard1, add_results_shard2], vec![1]),
    );
    let circuit = build_dummy_component_circuit(
        16,
        comp_loader_params,
        input.inputs.len(),
        input,
        &promise_results,
    )?;
    let output = circuit.compute_outputs()?;
    assert_eq!(output, SelectedDataShardsInMerkle::from_single_shard(ADD_MUL_RESULT.clone()));
    Ok(())
}

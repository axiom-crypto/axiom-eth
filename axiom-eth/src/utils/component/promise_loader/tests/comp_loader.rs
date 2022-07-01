use super::super::comp_loader::{
    BasicComponentCommiter, ComponentCommiter, SingleComponentLoader, SingleComponentLoaderImpl,
    SingleComponentLoaderParams,
};
use crate::Field;
use crate::{
    halo2curves::bn256::Fr,
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::component::{
        tests::{
            dummy_comp::{ComponentTypeAdd, LogicalInputAdd, LogicalOutputAdd},
            sum_comp::{ComponentTypeSum, SumLogicalInput},
        },
        utils::compute_poseidon,
        ComponentPromiseResult, ComponentPromiseResultsInMerkle, ComponentType, FlattenVirtualRow,
        FlattenVirtualTable, LogicalResult, PromiseShardMetadata,
    },
};
use halo2_base::{gates::circuit::builder::BaseCircuitBuilder, AssignedValue};
use itertools::Itertools;
use lazy_static::lazy_static;

type AddLogicalResult = LogicalResult<Fr, ComponentTypeAdd<Fr>>;
lazy_static! {
    static ref MOCK_GAMMA: Fr = Fr::from(100u64);
    static ref ADD_LOGICAL_RESUTLS_1: Vec<AddLogicalResult> = vec![
        AddLogicalResult::new(
            LogicalInputAdd { a: Fr::from(1u64), b: Fr::from(2u64) },
            LogicalOutputAdd { c: Fr::from(3u64) },
        ),
        AddLogicalResult::new(
            LogicalInputAdd { a: Fr::from(4u64), b: Fr::from(5u64) },
            LogicalOutputAdd { c: Fr::from(9u64) },
        ),
    ];
    static ref ADD_RESULTS_1_SQUEZZED_VT: Vec<Fr> =
        vec![1u64, 2, 3, 4, 5, 9].into_iter().map(Fr::from).collect_vec();
    static ref ADD_RESULTS_1_COMMIT: Fr = compute_poseidon(&ADD_RESULTS_1_SQUEZZED_VT);
    static ref ADD_RESULTS_1_RLC: Vec<Fr> = vec![Fr::from(10203), Fr::from(40509)];
    static ref ADD_LOGICAL_RESUTLS_2: Vec<AddLogicalResult> = vec![AddLogicalResult::new(
        LogicalInputAdd { a: Fr::from(8u64), b: Fr::from(9u64) },
        LogicalOutputAdd { c: Fr::from(17u64) },
    ),];
    static ref ADD_RESULTS_2_SQUEZZED_VT: Vec<Fr> =
        vec![8u64, 9, 17].into_iter().map(Fr::from).collect_vec();
    static ref ADD_RESULTS_2_COMMIT: Fr = compute_poseidon(&ADD_RESULTS_2_SQUEZZED_VT);
    static ref ADD_RESULTS_2_RLC: Vec<Fr> = vec![Fr::from(80917)];
    static ref ADD_RESULTS_LEAVES: Vec<PromiseShardMetadata<Fr>> = vec![
        PromiseShardMetadata::<Fr> {
            commit: *ADD_RESULTS_1_COMMIT,
            capacity: ADD_LOGICAL_RESUTLS_1.len()
        },
        PromiseShardMetadata::<Fr> {
            commit: *ADD_RESULTS_2_COMMIT,
            capacity: ADD_LOGICAL_RESUTLS_2.len()
        }
    ];
    static ref ADD_RESULTS_ROOT: Fr =
        compute_poseidon(&[*ADD_RESULTS_1_COMMIT, *ADD_RESULTS_2_COMMIT]);
}

fn squeeze_vritual_table<F: Field>(vt: FlattenVirtualTable<F>) -> Vec<F> {
    vt.into_iter().flat_map(|(f_in, f_out)| [f_in.fields, f_out.fields]).flatten().collect_vec()
}

fn assigned_flatten_vt_to_value<F: Field>(
    vt: FlattenVirtualTable<AssignedValue<F>>,
) -> FlattenVirtualTable<F> {
    vt.clone().into_iter().map(|(f_in, f_out)| (f_in.into(), f_out.into())).collect_vec()
}

fn logical_results_to_component_results<F: Field, T: ComponentType<F>>(
    lrs: Vec<LogicalResult<F, T>>,
) -> Vec<ComponentPromiseResult<F>> {
    lrs.into_iter().map(|lr| lr.into()).collect_vec()
}

fn verify_component_loader<F: Field, T: ComponentType<F>>(
    promise_results: ComponentPromiseResultsInMerkle<F>,
    comp_loader_params: SingleComponentLoaderParams,
    mock_gamma: F,
    expected_squeezed_vt: Vec<F>,
    expected_commit: F,
    expected_promise_rlcs: Vec<F>,
) {
    let mut comp_loader = SingleComponentLoaderImpl::<F, T>::new(comp_loader_params);
    comp_loader.load_promise_results(promise_results);
    let mut mock_builder = RlcCircuitBuilder::<F>::new(false, 32).use_k(18).use_lookup_bits(8);
    let (commit, flatten_vt) = comp_loader.assign_and_compute_commitment(&mut mock_builder);
    let flatten_vt_val = assigned_flatten_vt_to_value(flatten_vt.clone());
    let squeezed_vt = squeeze_vritual_table(flatten_vt_val);
    assert_eq!(squeezed_vt, expected_squeezed_vt);
    assert_eq!(*commit.value(), expected_commit);
    // Mock gamma to test RLC
    mock_builder.gamma = Some(mock_gamma);
    let (_, vt_rlcs) = comp_loader.generate_lookup_rlc(&mut mock_builder, &[], &flatten_vt);
    assert_eq!(vt_rlcs.into_iter().map(|rlc| *rlc.value()).collect_vec(), expected_promise_rlcs);
    // Clear to avoid warning outputs
    mock_builder.clear();
}

#[test]
fn test_component_loader_1_shard() {
    let promise_results =
        ComponentPromiseResultsInMerkle::from_single_shard(ADD_LOGICAL_RESUTLS_1.clone());

    let comp_loader_params = SingleComponentLoaderParams::new(2, vec![2]);
    verify_component_loader::<Fr, ComponentTypeAdd<Fr>>(
        promise_results,
        comp_loader_params,
        *MOCK_GAMMA,
        ADD_RESULTS_1_SQUEZZED_VT.clone(),
        *ADD_RESULTS_1_COMMIT,
        ADD_RESULTS_1_RLC.clone(),
    );
}

#[test]
fn test_component_loader_1_shard_3_times() {
    let promise_results = ComponentPromiseResultsInMerkle::new(
        ADD_RESULTS_LEAVES.clone(),
        // Read shard 0 three times.
        vec![
            (0, logical_results_to_component_results(ADD_LOGICAL_RESUTLS_1.clone())),
            (0, logical_results_to_component_results(ADD_LOGICAL_RESUTLS_1.clone())),
            (0, logical_results_to_component_results(ADD_LOGICAL_RESUTLS_1.clone())),
        ],
    );

    // Read 3 shards with capacity = 2.
    let comp_loader_params = SingleComponentLoaderParams::new(2, vec![2, 2, 2]);

    verify_component_loader::<Fr, ComponentTypeAdd<Fr>>(
        promise_results,
        comp_loader_params,
        *MOCK_GAMMA,
        [
            ADD_RESULTS_1_SQUEZZED_VT.clone(),
            ADD_RESULTS_1_SQUEZZED_VT.clone(),
            ADD_RESULTS_1_SQUEZZED_VT.clone(),
        ]
        .concat(),
        *ADD_RESULTS_ROOT,
        [ADD_RESULTS_1_RLC.clone(), ADD_RESULTS_1_RLC.clone(), ADD_RESULTS_1_RLC.clone()].concat(),
    );
}

#[test]
fn test_component_loader_2_shard() {
    let promise_results = ComponentPromiseResultsInMerkle::new(
        ADD_RESULTS_LEAVES.clone(),
        // Read shard 0 twice times and shard 1 once.
        vec![
            (0, logical_results_to_component_results(ADD_LOGICAL_RESUTLS_1.clone())),
            (1, logical_results_to_component_results(ADD_LOGICAL_RESUTLS_2.clone())),
            (0, logical_results_to_component_results(ADD_LOGICAL_RESUTLS_1.clone())),
        ],
    );

    // Read 3 shards with capacity = [2,1,2].
    let comp_loader_params = SingleComponentLoaderParams::new(2, vec![2, 1, 2]);

    verify_component_loader::<Fr, ComponentTypeAdd<Fr>>(
        promise_results,
        comp_loader_params,
        *MOCK_GAMMA,
        [
            ADD_RESULTS_1_SQUEZZED_VT.clone(),
            ADD_RESULTS_2_SQUEZZED_VT.clone(),
            ADD_RESULTS_1_SQUEZZED_VT.clone(),
        ]
        .concat(),
        *ADD_RESULTS_ROOT,
        [ADD_RESULTS_1_RLC.clone(), ADD_RESULTS_2_RLC.clone(), ADD_RESULTS_1_RLC.clone()].concat(),
    );
}

#[test]
fn test_basic_commiter() {
    let flatten_add_lrs: Vec<FlattenVirtualRow<Fr>> = ADD_LOGICAL_RESUTLS_1
        .clone()
        .into_iter()
        .flat_map(Vec::<FlattenVirtualRow<Fr>>::from)
        .collect_vec();
    let mut mock_builder = BaseCircuitBuilder::<Fr>::new(false).use_k(18).use_lookup_bits(8);
    let ctx = mock_builder.main(0);
    let assigned_flatten_add_lrs = flatten_add_lrs
        .into_iter()
        .map(|(f_lr_in, f_lr_out)| (f_lr_in.assign(ctx), f_lr_out.assign(ctx)))
        .collect_vec();
    let commit = BasicComponentCommiter::<Fr>::compute_commitment(
        &mut mock_builder,
        &assigned_flatten_add_lrs,
    );
    assert_eq!(*commit.value(), ADD_RESULTS_1_COMMIT.clone());
}

#[test]
fn test_basic_native_commiter() {
    let flatten_add_lrs: Vec<FlattenVirtualRow<Fr>> = ADD_LOGICAL_RESUTLS_1
        .clone()
        .into_iter()
        .flat_map(Vec::<FlattenVirtualRow<Fr>>::from)
        .collect_vec();
    let commit = BasicComponentCommiter::<Fr>::compute_native_commitment(&flatten_add_lrs);
    assert_eq!(commit, ADD_RESULTS_1_COMMIT.clone());
}

type SumLogicalResult = LogicalResult<Fr, ComponentTypeSum<Fr>>;
lazy_static! {
    static ref SUM_LOGICAL_RESUTLS_1: Vec<SumLogicalResult> = vec![
        SumLogicalResult::new(
            SumLogicalInput { to_sum: vec![3u64, 4u64, 5u64] },
            LogicalOutputAdd { c: Fr::from(12u64) },
        ),
        SumLogicalResult::new(
            SumLogicalInput { to_sum: vec![] },
            LogicalOutputAdd { c: Fr::from(0) },
        ),
    ];
    static ref SUM_RESULTS_1_SQUEZZED_VT: Vec<Fr> =
        vec![0u64, 3, 3, 0, 4, 7, 1, 5, 12, 1, 0, 0].into_iter().map(Fr::from).collect_vec();
    static ref SUM_RESULTS_1_COMMIT: Fr = compute_poseidon(&SUM_RESULTS_1_SQUEZZED_VT);
    static ref SUM_RESULTS_1_RLC: Vec<Fr> =
        vec![Fr::from(0), Fr::from(0), Fr::from(3040512), Fr::from(0)];
}

#[test]
fn test_component_loader_var_len_1_shard() {
    let promise_results =
        ComponentPromiseResultsInMerkle::from_single_shard(SUM_LOGICAL_RESUTLS_1.clone());

    let comp_loader_params = SingleComponentLoaderParams::new(2, vec![4]);
    verify_component_loader::<Fr, ComponentTypeSum<Fr>>(
        promise_results,
        comp_loader_params,
        *MOCK_GAMMA,
        SUM_RESULTS_1_SQUEZZED_VT.clone(),
        *SUM_RESULTS_1_COMMIT,
        SUM_RESULTS_1_RLC.clone(),
    );
}

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use halo2_base::AssignedValue;
use lazy_static::lazy_static;

use crate::{
    halo2_proofs::halo2curves::bn256::Fr,
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::component::{
        promise_collector::{PromiseCaller, PromiseCollector},
        tests::dummy_comp::LogicalOutputAdd,
        ComponentPromiseResultsInMerkle, ComponentType, LogicalResult,
    },
};

use super::dummy_comp::{ComponentTypeAdd, LogicalInputAdd};

type AddLogicalResult = LogicalResult<Fr, ComponentTypeAdd<Fr>>;
lazy_static! {
    static ref ADD_LOGICAL_RESUTLS_1: Vec<AddLogicalResult> = vec![
        AddLogicalResult::new(
            LogicalInputAdd { a: Fr::from(1u64), b: Fr::from(2u64) },
            // 1+2=3 but we give 4 here to check if the result is not computed in circuit.
            LogicalOutputAdd { c: Fr::from(4u64) },
        ),
        AddLogicalResult::new(
            LogicalInputAdd { a: Fr::from(4u64), b: Fr::from(5u64) },
            LogicalOutputAdd { c: Fr::from(9u64) },
        ),
    ];
    static ref ADD_LOGICAL_RESUTLS_2: Vec<AddLogicalResult> = vec![AddLogicalResult::new(
        LogicalInputAdd { a: Fr::from(8u64), b: Fr::from(9u64) },
        LogicalOutputAdd { c: Fr::from(17u64) },
    ),];
}

#[test]
fn test_promise_call_happy_path() {
    let pc = PromiseCollector::<Fr>::new(vec![ComponentTypeAdd::<Fr>::get_type_id()]);
    let shared_pc = Arc::new(Mutex::new(pc));

    let promise_results =
        ComponentPromiseResultsInMerkle::from_single_shard(ADD_LOGICAL_RESUTLS_1.clone());
    let mut results = HashMap::new();
    results.insert(ComponentTypeAdd::<Fr>::get_type_id(), promise_results);
    shared_pc.lock().unwrap().fulfill(&results);

    shared_pc.lock().unwrap().set_promise_results_ready(true);
    let mut mock_builder = RlcCircuitBuilder::<Fr>::new(false, 32).use_k(18).use_lookup_bits(8);
    let ctx = mock_builder.base.main(0);
    let a = ctx.load_constant(Fr::from(1u64));
    let b = ctx.load_constant(Fr::from(2u64));

    let caller = PromiseCaller::<Fr>::new(shared_pc.clone());
    let call_result = caller
        .call::<LogicalInputAdd<AssignedValue<Fr>>, ComponentTypeAdd<Fr>>(
            ctx,
            LogicalInputAdd { a, b },
        )
        .unwrap();
    // 1+2=3 but we give 4 here to check if the result is not computed in circuit.
    assert_eq!(*call_result.c.value(), Fr::from(4));
    // To avoid warning outputs.
    mock_builder.clear();
}

#[test]
#[should_panic]
fn test_promise_call_not_fulfilled() {
    let pc = PromiseCollector::<Fr>::new(vec![ComponentTypeAdd::<Fr>::get_type_id()]);
    let shared_pc = Arc::new(Mutex::new(pc));
    let caller = PromiseCaller::<Fr>::new(shared_pc.clone());
    shared_pc.lock().unwrap().set_promise_results_ready(true);
    let mut mock_builder = RlcCircuitBuilder::<Fr>::new(false, 32).use_k(18).use_lookup_bits(8);
    let ctx = mock_builder.base.main(0);
    let a = ctx.load_constant(Fr::from(1u64));
    let b = ctx.load_constant(Fr::from(2u64));
    caller
        .call::<LogicalInputAdd<AssignedValue<Fr>>, ComponentTypeAdd<Fr>>(
            ctx,
            LogicalInputAdd { a, b },
        )
        .unwrap();
}

#[test]
#[should_panic]
fn test_promise_call_missing_result() {
    let pc = PromiseCollector::<Fr>::new(vec![ComponentTypeAdd::<Fr>::get_type_id()]);
    let shared_pc = Arc::new(Mutex::new(pc));

    let promise_results =
        ComponentPromiseResultsInMerkle::from_single_shard(ADD_LOGICAL_RESUTLS_2.clone());
    let mut results = HashMap::new();
    results.insert(ComponentTypeAdd::<Fr>::get_type_id(), promise_results);
    shared_pc.lock().unwrap().fulfill(&results);

    shared_pc.lock().unwrap().set_promise_results_ready(true);
    let mut mock_builder = RlcCircuitBuilder::<Fr>::new(false, 32).use_k(18).use_lookup_bits(8);
    let ctx = mock_builder.base.main(0);
    let a = ctx.load_constant(Fr::from(1u64));
    let b = ctx.load_constant(Fr::from(2u64));

    let caller = PromiseCaller::<Fr>::new(shared_pc.clone());
    caller
        .call::<LogicalInputAdd<AssignedValue<Fr>>, ComponentTypeAdd<Fr>>(
            ctx,
            LogicalInputAdd { a, b },
        )
        .unwrap();
}

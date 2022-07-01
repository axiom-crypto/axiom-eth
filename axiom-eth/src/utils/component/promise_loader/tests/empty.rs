use crate::{
    halo2curves::bn256::Fr,
    utils::component::{circuit::PromiseBuilder, promise_loader::empty::EmptyPromiseLoader},
};

#[test]
fn test_extract_loader_params_per_component_type() {
    let result = EmptyPromiseLoader::<Fr>::extract_loader_params_per_component_type(&());
    assert_eq!(result, vec![]);
}

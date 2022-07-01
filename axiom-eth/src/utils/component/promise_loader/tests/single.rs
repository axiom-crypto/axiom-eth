use crate::{
    halo2curves::bn256::Fr,
    keccak::types::ComponentTypeKeccak,
    utils::component::{
        circuit::{LoaderParamsPerComponentType, PromiseBuilder},
        promise_loader::{
            comp_loader::SingleComponentLoaderParams,
            single::{PromiseLoader, PromiseLoaderParams},
        },
        ComponentType,
    },
};

#[test]
fn test_extract_loader_params_per_component_type() {
    let comp_loader_params = SingleComponentLoaderParams::new(3, vec![200]);
    let params = PromiseLoaderParams { comp_loader_params: comp_loader_params.clone() };
    let result =
        PromiseLoader::<Fr, ComponentTypeKeccak<Fr>>::extract_loader_params_per_component_type(
            &params,
        );
    assert_eq!(
        result,
        vec![LoaderParamsPerComponentType {
            component_type_id: ComponentTypeKeccak::<Fr>::get_type_id(),
            loader_params: comp_loader_params
        }]
    );
}

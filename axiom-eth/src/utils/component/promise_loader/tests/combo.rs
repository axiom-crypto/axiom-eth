use crate::{
    halo2curves::bn256::Fr,
    keccak::types::ComponentTypeKeccak,
    utils::component::{
        circuit::{LoaderParamsPerComponentType, PromiseBuilder},
        promise_loader::{
            combo::PromiseBuilderCombo,
            comp_loader::SingleComponentLoaderParams,
            single::{PromiseLoader, PromiseLoaderParams},
        },
        tests::dummy_comp::ComponentTypeAdd,
        ComponentType,
    },
};

#[test]
fn test_extract_loader_params_per_component_type() {
    type Loader = PromiseBuilderCombo<
        Fr,
        PromiseLoader<Fr, ComponentTypeKeccak<Fr>>,
        PromiseLoader<Fr, ComponentTypeAdd<Fr>>,
    >;
    let comp_loader_params_1 = SingleComponentLoaderParams::new(3, vec![200]);
    let comp_loader_params_2 = SingleComponentLoaderParams::new(2, vec![20]);
    let params = (
        PromiseLoaderParams { comp_loader_params: comp_loader_params_1.clone() },
        PromiseLoaderParams { comp_loader_params: comp_loader_params_2.clone() },
    );
    let result = Loader::extract_loader_params_per_component_type(&params);
    assert_eq!(
        result,
        vec![
            LoaderParamsPerComponentType {
                component_type_id: ComponentTypeKeccak::<Fr>::get_type_id(),
                loader_params: comp_loader_params_1
            },
            LoaderParamsPerComponentType {
                component_type_id: ComponentTypeAdd::<Fr>::get_type_id(),
                loader_params: comp_loader_params_2
            }
        ]
    );
}

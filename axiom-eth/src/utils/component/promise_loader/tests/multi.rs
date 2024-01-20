use halo2_base::{gates::GateInstructions, AssignedValue};

use crate::{
    component_type_list,
    halo2curves::bn256::Fr,
    keccak::types::ComponentTypeKeccak,
    rlc::{chip::RlcChip, circuit::builder::RlcContextPair},
    utils::component::{
        circuit::{LoaderParamsPerComponentType, PromiseBuilder},
        promise_loader::{
            comp_loader::SingleComponentLoaderParams,
            multi::{MultiPromiseLoader, MultiPromiseLoaderParams, RlcAdapter},
        },
        tests::dummy_comp::{ComponentTypeAdd, ComponentTypeAddMul},
        types::{EmptyComponentType, Flatten},
        ComponentType, ComponentTypeId,
    },
};

// Just for teseting purpose
struct DummyRlcAdapter {}
impl RlcAdapter<Fr> for DummyRlcAdapter {
    fn to_rlc(
        _ctx_pair: RlcContextPair<Fr>,
        _gate: &impl GateInstructions<Fr>,
        _rlc: &RlcChip<Fr>,
        _type_id: &ComponentTypeId,
        _io_pairs: &[(Flatten<AssignedValue<Fr>>, Flatten<AssignedValue<Fr>>)],
    ) -> Vec<AssignedValue<Fr>> {
        vec![]
    }
}

#[test]
fn test_extract_loader_params_per_component_type() {
    type Dependencies = component_type_list!(
        Fr,
        ComponentTypeAdd<Fr>,
        ComponentTypeAddMul<Fr>,
        ComponentTypeKeccak<Fr>
    );
    type Loader = MultiPromiseLoader<Fr, EmptyComponentType<Fr>, Dependencies, DummyRlcAdapter>;

    let comp_loader_params_1 = SingleComponentLoaderParams::new(3, vec![200]);
    let comp_loader_params_2 = SingleComponentLoaderParams::new(2, vec![500]);
    let comp_loader_params_3 = SingleComponentLoaderParams::new(5, vec![20]);

    let expected_results = vec![
        LoaderParamsPerComponentType {
            component_type_id: ComponentTypeAdd::<Fr>::get_type_id(),
            loader_params: comp_loader_params_1.clone(),
        },
        LoaderParamsPerComponentType {
            component_type_id: ComponentTypeAddMul::<Fr>::get_type_id(),
            loader_params: comp_loader_params_2.clone(),
        },
        LoaderParamsPerComponentType {
            component_type_id: ComponentTypeKeccak::<Fr>::get_type_id(),
            loader_params: comp_loader_params_3.clone(),
        },
    ];

    let params = MultiPromiseLoaderParams {
        params_per_component: [
            (ComponentTypeKeccak::<Fr>::get_type_id(), comp_loader_params_3),
            (ComponentTypeAddMul::<Fr>::get_type_id(), comp_loader_params_2),
            (ComponentTypeAdd::<Fr>::get_type_id(), comp_loader_params_1),
        ]
        .into_iter()
        .collect(),
    };
    let result = Loader::extract_loader_params_per_component_type(&params);
    assert_eq!(result, expected_results);
}

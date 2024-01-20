use std::marker::PhantomData;

use crate::rlc::circuit::builder::RlcCircuitBuilder;
use crate::utils::component::circuit::LoaderParamsPerComponentType;
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::ConstraintSystem};

use crate::Field;

use crate::utils::component::{
    circuit::{ComponentBuilder, PromiseBuilder},
    promise_collector::{PromiseCallsGetter, PromiseCommitSetter, PromiseResultsGetter},
    ComponentTypeId,
};

#[derive(Default)]
/// Empty promise loader.
pub struct EmptyPromiseLoader<F: Field>(PhantomData<F>);

impl<F: Field> ComponentBuilder<F> for EmptyPromiseLoader<F> {
    type Config = ();
    type Params = ();

    fn new(_params: Self::Params) -> Self {
        Self(PhantomData)
    }

    fn get_params(&self) -> Self::Params {}

    fn clear_witnesses(&mut self) {}

    fn configure_with_params(
        _meta: &mut ConstraintSystem<F>,
        _params: Self::Params,
    ) -> Self::Config {
    }
    fn calculate_params(&mut self) -> Self::Params {}
}

impl<F: Field> PromiseBuilder<F> for EmptyPromiseLoader<F> {
    fn get_component_type_dependencies() -> Vec<ComponentTypeId> {
        vec![]
    }
    fn extract_loader_params_per_component_type(
        _params: &Self::Params,
    ) -> Vec<LoaderParamsPerComponentType> {
        vec![]
    }
    fn fulfill_promise_results(&mut self, _promise_results_getter: &impl PromiseResultsGetter<F>) {
        // Do nothing.
    }
    fn virtual_assign_phase0(
        &mut self,
        _builder: &mut RlcCircuitBuilder<F>,
        _promise_commit_setter: &mut impl PromiseCommitSetter<F>,
    ) {
        // Do nothing.
    }
    fn raw_synthesize_phase0(&mut self, _config: &Self::Config, _layouter: &mut impl Layouter<F>) {
        // Do nothing.
    }
    fn virtual_assign_phase1(
        &mut self,
        _builder: &mut RlcCircuitBuilder<F>,
        _promise_calls_getter: &mut impl PromiseCallsGetter<F>,
    ) {
        // Do nothing.
    }
    fn raw_synthesize_phase1(&mut self, _config: &Self::Config, _layouter: &mut impl Layouter<F>) {
        // Do nothing.
    }
}

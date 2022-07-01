use std::marker::PhantomData;

use halo2_base::halo2_proofs::{circuit::Layouter, plonk::ConstraintSystem};

use crate::{
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::component::{
        circuit::{ComponentBuilder, LoaderParamsPerComponentType, PromiseBuilder},
        promise_collector::{PromiseCallsGetter, PromiseCommitSetter, PromiseResultsGetter},
        ComponentTypeId,
    },
    Field,
};

pub struct PromiseBuilderCombo<F: Field, FIRST: PromiseBuilder<F>, SECOND: PromiseBuilder<F>> {
    pub to_combine: (FIRST, SECOND),
    _phantom: PhantomData<(F, FIRST, SECOND)>,
}

impl<F: Field, FIRST: PromiseBuilder<F>, SECOND: PromiseBuilder<F>>
    PromiseBuilderCombo<F, FIRST, SECOND>
{
}

impl<F: Field, FIRST: PromiseBuilder<F>, SECOND: PromiseBuilder<F>> ComponentBuilder<F>
    for PromiseBuilderCombo<F, FIRST, SECOND>
{
    type Config = (FIRST::Config, SECOND::Config);
    type Params = (FIRST::Params, SECOND::Params);

    fn new(params: Self::Params) -> Self {
        Self { to_combine: (FIRST::new(params.0), SECOND::new(params.1)), _phantom: PhantomData }
    }
    fn get_params(&self) -> Self::Params {
        (self.to_combine.0.get_params(), self.to_combine.1.get_params())
    }
    fn clear_witnesses(&mut self) {
        self.to_combine.0.clear_witnesses();
        self.to_combine.1.clear_witnesses();
    }

    fn calculate_params(&mut self) -> Self::Params {
        (self.to_combine.0.calculate_params(), self.to_combine.1.calculate_params())
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        (
            FIRST::configure_with_params(meta, params.0),
            SECOND::configure_with_params(meta, params.1),
        )
    }
}

impl<F: Field, FIRST: PromiseBuilder<F>, SECOND: PromiseBuilder<F>> PromiseBuilder<F>
    for PromiseBuilderCombo<F, FIRST, SECOND>
{
    fn get_component_type_dependencies() -> Vec<ComponentTypeId> {
        [FIRST::get_component_type_dependencies(), SECOND::get_component_type_dependencies()]
            .concat()
    }
    fn extract_loader_params_per_component_type(
        params: &Self::Params,
    ) -> Vec<LoaderParamsPerComponentType> {
        FIRST::extract_loader_params_per_component_type(&params.0)
            .into_iter()
            .chain(SECOND::extract_loader_params_per_component_type(&params.1))
            .collect()
    }

    fn fulfill_promise_results(&mut self, promise_results_getter: &impl PromiseResultsGetter<F>) {
        self.to_combine.0.fulfill_promise_results(promise_results_getter);
        self.to_combine.1.fulfill_promise_results(promise_results_getter);
    }
    fn virtual_assign_phase0(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_commit_setter: &mut impl PromiseCommitSetter<F>,
    ) {
        self.to_combine.0.virtual_assign_phase0(builder, promise_commit_setter);
        self.to_combine.1.virtual_assign_phase0(builder, promise_commit_setter);
    }
    fn raw_synthesize_phase0(&mut self, config: &Self::Config, layouter: &mut impl Layouter<F>) {
        self.to_combine.0.raw_synthesize_phase0(&config.0, layouter);
        self.to_combine.1.raw_synthesize_phase0(&config.1, layouter);
    }
    fn virtual_assign_phase1(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_calls_getter: &mut impl PromiseCallsGetter<F>,
    ) {
        self.to_combine.0.virtual_assign_phase1(builder, promise_calls_getter);
        self.to_combine.1.virtual_assign_phase1(builder, promise_calls_getter);
    }
    fn raw_synthesize_phase1(&mut self, config: &Self::Config, layouter: &mut impl Layouter<F>) {
        self.to_combine.0.raw_synthesize_phase1(&config.0, layouter);
        self.to_combine.1.raw_synthesize_phase1(&config.1, layouter);
    }
}

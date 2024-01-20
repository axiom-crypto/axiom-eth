use halo2_base::AssignedValue;

use crate::{
    utils::component::{circuit::PromiseBuilder, types::LogicalEmpty, ComponentType},
    Field,
};

use super::{
    combo::PromiseBuilderCombo,
    empty::EmptyPromiseLoader,
    multi::{ComponentTypeList, MultiPromiseLoader, RlcAdapter},
    single,
};

/// Sub-trait for dummy fulfillment. Only used to create dummy circuits for
/// the purpose of proving/verifying key generation.
pub trait DummyPromiseBuilder<F: Field>: PromiseBuilder<F> {
    /// This should be the same behavior as `fulfill_promise_results` but with
    /// dummy results. The exact configuration of the results is determined by
    /// the `loader_params` of the promise builder.
    fn fulfill_dummy_promise_results(&mut self);
}

impl<F: Field> DummyPromiseBuilder<F> for EmptyPromiseLoader<F> {
    fn fulfill_dummy_promise_results(&mut self) {}
}

impl<F: Field, T: ComponentType<F>> DummyPromiseBuilder<F> for single::PromiseLoader<F, T> {
    fn fulfill_dummy_promise_results(&mut self) {
        self.comp_loader.load_dummy_promise_results();
    }
}

impl<F: Field, FIRST: DummyPromiseBuilder<F>, SECOND: DummyPromiseBuilder<F>> DummyPromiseBuilder<F>
    for PromiseBuilderCombo<F, FIRST, SECOND>
{
    fn fulfill_dummy_promise_results(&mut self) {
        let (first, second) = &mut self.to_combine;
        first.fulfill_dummy_promise_results();
        second.fulfill_dummy_promise_results();
    }
}

impl<
        F: Field,
        VT: ComponentType<
            F,
            OutputValue = LogicalEmpty<F>,
            OutputWitness = LogicalEmpty<AssignedValue<F>>,
        >,
        CLIST: ComponentTypeList<F>,
        A: RlcAdapter<F>,
    > DummyPromiseBuilder<F> for MultiPromiseLoader<F, VT, CLIST, A>
{
    fn fulfill_dummy_promise_results(&mut self) {
        for comp_loader in &mut self.comp_loaders {
            comp_loader.load_dummy_promise_results();
        }
    }
}

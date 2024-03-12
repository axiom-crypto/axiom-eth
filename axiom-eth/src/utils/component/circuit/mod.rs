use crate::Field;
use crate::{rlc::circuit::builder::RlcCircuitBuilder, utils::build_utils::dummy::DummyFrom};
use getset::Getters;
use halo2_base::{
    halo2_proofs::{circuit::Layouter, plonk::ConstraintSystem},
    AssignedValue,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{
    promise_collector::{
        PromiseCaller, PromiseCallsGetter, PromiseCommitSetter, PromiseResultsGetter,
    },
    promise_loader::comp_loader::SingleComponentLoaderParams,
    types::FixLenLogical,
    ComponentType, ComponentTypeId, FlattenVirtualTable, LogicalResult,
};

mod comp_circuit_impl;
pub use comp_circuit_impl::ComponentCircuitImpl;

pub trait ComponentBuilder<F: Field> {
    type Config: Clone = ();
    type Params: Clone + Default = ();

    /// Create Self.
    fn new(params: Self::Params) -> Self;
    /// Get params for this module.
    fn get_params(&self) -> Self::Params;
    /// Clear all stored witnesses. Data should be untouched.
    fn clear_witnesses(&mut self) {}
    /// Configure this module with params.
    // Alas we cannot have default implementation only for Self::Config = ().
    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config;
    /// Calculate params for this module.
    fn calculate_params(&mut self) -> Self::Params;
}

/// CoreBuilder must specify its output format.
pub trait CoreBuilderParams {
    /// Return the output capacity.
    fn get_output_params(&self) -> CoreBuilderOutputParams;
}
#[derive(Clone, Default, Getters)]
pub struct CoreBuilderOutputParams {
    /// Capacities for each shard.
    #[getset(get = "pub")]
    cap_per_shard: Vec<usize>,
}
impl CoreBuilderOutputParams {
    /// create a CoreBuilderOutputParams
    pub fn new(cap_per_shard: Vec<usize>) -> Self {
        assert!(cap_per_shard.is_empty() || cap_per_shard.len().is_power_of_two());
        Self { cap_per_shard }
    }
}
impl CoreBuilderParams for CoreBuilderOutputParams {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        self.clone()
    }
}
/// Input for CoreBuilder.
/// TODO: specify its output capacity.
pub trait CoreBuilderInput<F: Field> = Serialize + DeserializeOwned + Clone + 'static;

/// Output for CoreBuilder which is determined at phase0.
pub struct CoreBuilderOutput<F: Field, T: ComponentType<F>> {
    /// Public instances except the output commit.
    pub public_instances: Vec<AssignedValue<F>>,
    /// Flatten output virtual table.
    pub virtual_table: FlattenVirtualTable<AssignedValue<F>>,
    /// Value of logical results.
    pub logical_results: Vec<LogicalResult<F, T>>,
}

pub trait CoreBuilder<F: Field>: ComponentBuilder<F, Params: CoreBuilderParams> {
    type CompType: ComponentType<F>;
    type PublicInstanceValue: FixLenLogical<F>;
    type PublicInstanceWitness: FixLenLogical<AssignedValue<F>>;
    type CoreInput: CoreBuilderInput<F> + DummyFrom<Self::Params>;
    /// Feed inputs to this module.
    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()>;
    /// Generate witnesses for phase0. Any data passing to other steps should be stored inside `self`.
    /// Return `(<output commit>, <other public instances>)`.
    fn virtual_assign_phase0(
        &mut self,
        // TODO: This could be replaced with a more generic CircuitBuilder. Question: can be CircuitBuilder treated as something like PromiseCircuit?
        builder: &mut RlcCircuitBuilder<F>,
        // Core circuits can make promise calls.
        promise_caller: PromiseCaller<F>,
        // TODO: Output commitment
    ) -> CoreBuilderOutput<F, Self::CompType>;
    /// Synthesize for phase0. Any data passing to other steps should be stored inside `self`.
    #[allow(unused_variables)]
    fn raw_synthesize_phase0(&mut self, config: &Self::Config, layouter: &mut impl Layouter<F>) {}
    /// Generate witnesses for phase1. Any data passing to other steps should be stored inside `self`.
    #[allow(unused_variables)]
    fn virtual_assign_phase1(&mut self, builder: &mut RlcCircuitBuilder<F>) {}
    /// Synthesize for phase1. Any data passing to other steps should be stored inside `self`.
    #[allow(unused_variables)]
    fn raw_synthesize_phase1(&mut self, config: &Self::Config, layouter: &mut impl Layouter<F>) {}
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct LoaderParamsPerComponentType {
    pub component_type_id: ComponentTypeId,
    pub loader_params: SingleComponentLoaderParams,
}

/// A ComponentModule load promise results from other components and owns some columns and corresponding gates.
/// All ComponentModules in a single circuit share a RlcCircuitBuilder and they communicate with each other through PromiseCollector.
pub trait PromiseBuilder<F: Field>: ComponentBuilder<F> {
    /// Get component type dependencies of this ComponentBuilder in a deterministic order.
    fn get_component_type_dependencies() -> Vec<ComponentTypeId>;
    /// Extract loader params per component type from circuit params.
    /// Assumption: Return value is in a deterministic order which we use to compute the promise commit.
    fn extract_loader_params_per_component_type(
        params: &Self::Params,
    ) -> Vec<LoaderParamsPerComponentType>;
    /// Fulfill promise results.
    fn fulfill_promise_results(&mut self, promise_results_getter: &impl PromiseResultsGetter<F>);
    /// Generate witnesses for phase0. Any data passing to other steps should be stored inside `self`.
    /// Also need to set promise result commits.
    fn virtual_assign_phase0(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_commit_setter: &mut impl PromiseCommitSetter<F>,
    );
    /// Synthesize for phase0. Any data passing to other steps should be stored inside `self`.
    fn raw_synthesize_phase0(&mut self, config: &Self::Config, layouter: &mut impl Layouter<F>);
    /// Generate witnesses for phase1. Any data passing to other steps should be stored inside `self`.
    fn virtual_assign_phase1(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_calls_getter: &mut impl PromiseCallsGetter<F>,
    );
    /// Synthesize for phase1. Any data passing to other steps should be stored inside `self`.
    fn raw_synthesize_phase1(&mut self, config: &Self::Config, layouter: &mut impl Layouter<F>);
}

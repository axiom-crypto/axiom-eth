use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};

use crate::Field;
use anyhow::anyhow;
use getset::{CopyGetters, Setters};
use halo2_base::{AssignedValue, Context, ContextTag};
use itertools::Itertools;

use super::{
    types::Flatten, ComponentPromiseResultsInMerkle, ComponentType, ComponentTypeId,
    GroupedPromiseCalls, GroupedPromiseResults, PromiseCallWitness, TypelessLogicalInput,
    TypelessPromiseCall,
};

// (flatten input value, flatten input witness, flatten output witness)
// <flatten input value> is for dedup.
pub type PromiseResultWitness<F> = (Box<dyn PromiseCallWitness<F>>, Flatten<AssignedValue<F>>);

pub type SharedPromiseCollector<F> = Arc<Mutex<PromiseCollector<F>>>;
/// Newtype for [SharedPromiseCollector] with promise `call` functionality.
#[derive(Clone, Debug)]
pub struct PromiseCaller<F: Field>(pub SharedPromiseCollector<F>);
impl<F: Field> PromiseCaller<F> {
    /// Create a PromiseCallerWrap
    pub fn new(shared_promise_collector: SharedPromiseCollector<F>) -> Self {
        Self(shared_promise_collector)
    }
    /// Make a promise call.
    pub fn call<P: PromiseCallWitness<F>, B: ComponentType<F>>(
        &self,
        ctx: &mut Context<F>,
        input_witness: P,
    ) -> anyhow::Result<B::OutputWitness> {
        assert_eq!(input_witness.get_component_type_id(), B::get_type_id());
        let witness_output_flatten =
            self.0.lock().unwrap().call_impl(ctx, Box::new(input_witness))?;
        B::OutputWitness::try_from(witness_output_flatten)
    }
}

#[derive(CopyGetters, Setters, Debug)]
pub struct PromiseCollector<F: Field> {
    dependencies_lookup: HashSet<ComponentTypeId>,
    dependencies: Vec<ComponentTypeId>,
    // TypeId -> (ContextTag -> Vec<PromiseResultWitness>)
    // ContextTag is to support multi-threaded calls while maintaining deterministic in-circuit assignment order.
    witness_grouped_calls:
        HashMap<ComponentTypeId, BTreeMap<ContextTag, Vec<PromiseResultWitness<F>>>>,
    // Promise results for each component type.
    value_results: HashMap<ComponentTypeId, ComponentPromiseResultsInMerkle<F>>,
    // map version of `value_results` for quick lookup promise results.
    value_results_lookup: HashMap<ComponentTypeId, HashMap<TypelessLogicalInput, Vec<F>>>,
    witness_commits: HashMap<ComponentTypeId, AssignedValue<F>>,
    #[getset(get_copy = "pub", set = "pub")]
    promise_results_ready: bool,
}

/// This is to limit PromiseCollector's interfaces exposed to implementaion.
pub trait PromiseCallsGetter<F: Field> {
    /// Get promise calls by component type id. This is used to add these promises into lookup columns.
    /// TODO: This should return `Vec<PromiseResultWitness<F>>` because the order is determined at that time. But it's tricky to
    /// flatten the BTreeMap without cloning Box.
    fn get_calls_by_component_type_id(
        &self,
        component_type_id: &ComponentTypeId,
    ) -> Option<&BTreeMap<ContextTag, Vec<PromiseResultWitness<F>>>>;
}

/// This is to limit PromiseCollector's interfaces exposed to implementaion.
pub trait PromiseResultsGetter<F: Field> {
    /// Get promise results by component type id. This is used to add these promises into lookup columns.
    fn get_results_by_component_type_id(
        &self,
        component_type_id: &ComponentTypeId,
    ) -> Option<&ComponentPromiseResultsInMerkle<F>>;
}

/// This is to limit PromiseCollector's interfaces exposed to implementaion.
pub trait PromiseCommitSetter<F: Field> {
    /// Get promise results by component type id. This is used to add these promises into lookup columns.
    fn set_commit_by_component_type_id(
        &mut self,
        component_type_id: ComponentTypeId,
        commit: AssignedValue<F>,
    );
}

impl<F: Field> PromiseCollector<F> {
    pub fn new(dependencies: Vec<ComponentTypeId>) -> Self {
        Self {
            dependencies_lookup: dependencies.clone().into_iter().collect(),
            dependencies,
            witness_grouped_calls: Default::default(),
            value_results: Default::default(),
            value_results_lookup: Default::default(),
            witness_commits: Default::default(),
            promise_results_ready: false,
        }
    }

    pub fn clear_witnesses(&mut self) {
        self.witness_grouped_calls.clear();
        self.witness_commits.clear();
        // self.result should not be cleared because it comes from external.
    }

    /// Get promise commit by component type id.
    pub fn get_commit_by_component_type_id(
        &self,
        component_type_id: &ComponentTypeId,
    ) -> Option<AssignedValue<F>> {
        self.witness_commits.get(component_type_id).copied()
    }

    /// Return dedup promises.
    /// For each component type, the calls are sorted and deduped so that the returned order is deterministic.
    pub fn get_deduped_calls(&self) -> GroupedPromiseCalls {
        self.witness_grouped_calls
            .iter()
            .map(|(type_id, calls)| {
                (
                    type_id.clone(),
                    calls
                        .iter()
                        .flat_map(|(_, calls_per_context)| {
                            calls_per_context.iter().map(|(p, _)| TypelessPromiseCall {
                                capacity: p.get_capacity(),
                                logical_input: p.to_typeless_logical_input(),
                            })
                        })
                        .sorted() // sorting to ensure the order is deterministic.
                        // Note: likely not enough promise calls to be worth using par_sort
                        .dedup()
                        .collect_vec(),
                )
            })
            .collect()
    }

    /// Fulfill promise calls with the coressponding results.
    pub fn fulfill(&mut self, results: &GroupedPromiseResults<F>) {
        assert!(!self.promise_results_ready);
        for dep in &self.dependencies {
            if let Some(results_per_comp) = results.get(dep) {
                let results_per_comp = results_per_comp.clone();
                // TODO: check if it has already been fulfilled.
                self.value_results_lookup.insert(
                    dep.clone(),
                    results_per_comp
                        .shards
                        .clone()
                        .into_iter()
                        .flat_map(|(_, data)| data)
                        .collect(),
                );
                self.value_results.insert(dep.clone(), results_per_comp);
            }
        }
    }

    pub(crate) fn call_impl(
        &mut self,
        ctx: &mut Context<F>,
        witness_input: Box<dyn PromiseCallWitness<F>>,
    ) -> anyhow::Result<Flatten<AssignedValue<F>>> {
        // Special case: virtual call
        let is_virtual = witness_input.get_capacity() == 0;

        let component_type_id = witness_input.get_component_type_id();
        if !is_virtual && !self.dependencies_lookup.contains(&component_type_id) {
            return Err(anyhow!("Unsupport component type id {:?}.", component_type_id));
        }

        let value_serialized_input = witness_input.to_typeless_logical_input();

        let call_results = self.value_results_lookup.get(&component_type_id);
        // Virtual component type promise calls always go to the else branch.
        let witness_output = if !is_virtual && self.promise_results_ready {
            // Hack: there is no direct way to get field size information.
            let mut flatten_output = witness_input.get_mock_output();
            // If promise results are fullfilled, use the results directly.
            // Crash if the promise result is not fullfilled.
            flatten_output.fields =
                call_results.unwrap().get(&value_serialized_input).unwrap().clone();
            flatten_output.assign(ctx)
        } else {
            witness_input.get_mock_output().assign(ctx)
        };
        self.witness_grouped_calls
            .entry(component_type_id)
            .or_default()
            .entry(ctx.tag())
            .or_default()
            .push((witness_input, witness_output.clone()));
        Ok(witness_output)
    }
}

impl<F: Field> PromiseCallsGetter<F> for PromiseCollector<F> {
    fn get_calls_by_component_type_id(
        &self,
        component_type_id: &ComponentTypeId,
    ) -> Option<&BTreeMap<ContextTag, Vec<PromiseResultWitness<F>>>> {
        self.witness_grouped_calls.get(component_type_id)
    }
}

impl<F: Field> PromiseResultsGetter<F> for PromiseCollector<F> {
    fn get_results_by_component_type_id(
        &self,
        component_type_id: &ComponentTypeId,
    ) -> Option<&ComponentPromiseResultsInMerkle<F>> {
        self.value_results.get(component_type_id)
    }
}

impl<F: Field> PromiseCommitSetter<F> for PromiseCollector<F> {
    fn set_commit_by_component_type_id(
        &mut self,
        component_type_id: ComponentTypeId,
        commit: AssignedValue<F>,
    ) {
        log::debug!("component_type_id: {} commit: {:?}", component_type_id, commit.value());
        self.witness_commits.insert(component_type_id, commit);
    }
}

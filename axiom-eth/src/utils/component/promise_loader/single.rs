#![allow(clippy::type_complexity)]
use std::marker::PhantomData;

use getset::{CopyGetters, Setters};
use halo2_base::{
    halo2_proofs::{
        circuit::Layouter,
        plonk::{ConstraintSystem, SecondPhase},
    },
    virtual_region::{
        copy_constraints::SharedCopyConstraintManager, lookups::basic::BasicDynLookupConfig,
    },
    AssignedValue,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::component::{
        circuit::{ComponentBuilder, LoaderParamsPerComponentType, PromiseBuilder},
        promise_collector::{PromiseCallsGetter, PromiseCommitSetter, PromiseResultsGetter},
        types::Flatten,
        ComponentType, ComponentTypeId,
    },
    Field,
};

use super::comp_loader::{
    SingleComponentLoader, SingleComponentLoaderImpl, SingleComponentLoaderParams,
};

#[derive(Clone)]
pub struct PromiseLoaderConfig {
    pub dyn_lookup_config: BasicDynLookupConfig<1>,
}

#[derive(Default, Clone, Debug, Hash, Serialize, Deserialize)]
pub struct PromiseLoaderParams {
    pub comp_loader_params: SingleComponentLoaderParams,
}

impl PromiseLoaderParams {
    pub fn new(comp_loader_params: SingleComponentLoaderParams) -> Self {
        Self { comp_loader_params }
    }
    pub fn new_for_one_shard(capacity: usize) -> Self {
        Self { comp_loader_params: SingleComponentLoaderParams::new(0, vec![capacity]) }
    }
}

/// PromiseLoader loads promises of a component type. It owns a lookup table dedicated for the component type.
/// The size of promise result it receives MUST match its capacity.
#[derive(Setters, CopyGetters)]
pub struct PromiseLoader<F: Field, T: ComponentType<F>> {
    params: PromiseLoaderParams,
    witness_promise_results: Option<Vec<(Flatten<AssignedValue<F>>, Flatten<AssignedValue<F>>)>>,
    // (to lookup, lookup table)
    witness_rlc_lookup: Option<(Vec<AssignedValue<F>>, Vec<AssignedValue<F>>)>,
    // A bit hacky..
    witness_gen_only: bool,
    copy_manager: Option<SharedCopyConstraintManager<F>>,
    pub(super) comp_loader: Box<dyn SingleComponentLoader<F>>,
    _phantom: PhantomData<T>,
}

impl<F: Field, T: ComponentType<F>> ComponentBuilder<F> for PromiseLoader<F, T> {
    type Config = PromiseLoaderConfig;
    type Params = PromiseLoaderParams;

    // Create PromiseLoader
    fn new(params: PromiseLoaderParams) -> Self {
        Self {
            params: params.clone(),
            witness_promise_results: None,
            witness_rlc_lookup: None,
            witness_gen_only: false,
            copy_manager: None,
            comp_loader: Box::new(SingleComponentLoaderImpl::<F, T>::new(
                params.comp_loader_params,
            )),
            _phantom: PhantomData,
        }
    }

    fn get_params(&self) -> Self::Params {
        self.params.clone()
    }

    fn clear_witnesses(&mut self) {
        self.witness_promise_results = None;
        self.witness_rlc_lookup = None;
        self.copy_manager = None;
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<F>,
        _params: Self::Params,
    ) -> Self::Config {
        // TODO: adjust num of columns based on params.
        let dyn_lookup_config = BasicDynLookupConfig::new(meta, || SecondPhase, 1);
        Self::Config { dyn_lookup_config }
    }
    fn calculate_params(&mut self) -> Self::Params {
        self.params.clone()
    }
}

impl<F: Field, T: ComponentType<F>> PromiseBuilder<F> for PromiseLoader<F, T> {
    fn get_component_type_dependencies() -> Vec<ComponentTypeId> {
        vec![T::get_type_id()]
    }
    fn extract_loader_params_per_component_type(
        params: &Self::Params,
    ) -> Vec<LoaderParamsPerComponentType> {
        vec![LoaderParamsPerComponentType {
            component_type_id: T::get_type_id(),
            loader_params: params.comp_loader_params.clone(),
        }]
    }
    fn fulfill_promise_results(&mut self, promise_results_getter: &impl PromiseResultsGetter<F>) {
        let component_type_id = self.comp_loader.get_component_type_id();
        let promise_results = promise_results_getter
            .get_results_by_component_type_id(&component_type_id)
            .unwrap_or_else(|| {
                panic!("missing promise results for component type id {:?}", component_type_id)
            });
        self.comp_loader.load_promise_results(promise_results.clone());
        // TODO: shard size check
    }

    fn virtual_assign_phase0(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_commit_setter: &mut impl PromiseCommitSetter<F>,
    ) {
        assert!(self.witness_promise_results.is_none());
        self.witness_gen_only = builder.witness_gen_only();

        let (commit, witness_promise_results) =
            self.comp_loader.assign_and_compute_commitment(builder);

        let component_type_id = self.comp_loader.get_component_type_id();
        promise_commit_setter.set_commit_by_component_type_id(component_type_id, commit);

        self.witness_promise_results = Some(witness_promise_results);
    }

    fn raw_synthesize_phase0(&mut self, _config: &Self::Config, _layouter: &mut impl Layouter<F>) {
        // Do nothing.
    }

    fn virtual_assign_phase1(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_calls_getter: &mut impl PromiseCallsGetter<F>,
    ) {
        assert!(self.witness_promise_results.is_some());
        let calls = promise_calls_getter
            .get_calls_by_component_type_id(&self.comp_loader.get_component_type_id())
            .unwrap()
            .values()
            .flatten()
            .collect_vec();
        let (to_lookup_rlc, lookup_table_rlc) = self.comp_loader.generate_lookup_rlc(
            builder,
            &calls,
            self.witness_promise_results.as_ref().unwrap(),
        );

        self.witness_rlc_lookup = Some((to_lookup_rlc, lookup_table_rlc));

        self.copy_manager = Some(builder.copy_manager().clone());
    }

    fn raw_synthesize_phase1(&mut self, config: &Self::Config, layouter: &mut impl Layouter<F>) {
        assert!(self.witness_rlc_lookup.is_some());

        let (to_lookup, lookup_table) = self.witness_rlc_lookup.as_ref().unwrap();
        let dyn_lookup_config = &config.dyn_lookup_config;

        let copy_manager = (!self.witness_gen_only).then(|| self.copy_manager.as_ref().unwrap());
        dyn_lookup_config.assign_virtual_table_to_raw(
            layouter.namespace(|| {
                format!(
                    "promise loader adds advice to lookup for {}",
                    self.comp_loader.get_component_type_name()
                )
            }),
            lookup_table.iter().map(|a| [*a; 1]),
            copy_manager,
        );

        dyn_lookup_config.assign_virtual_to_lookup_to_raw(
            layouter.namespace(|| {
                format!(
                    "promise loader loads lookup table {}",
                    self.comp_loader.get_component_type_name()
                )
            }),
            to_lookup.iter().map(|a| [*a; 1]),
            copy_manager,
        );
    }
}

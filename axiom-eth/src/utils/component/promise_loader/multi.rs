#![allow(clippy::type_complexity)]
use std::{collections::HashMap, marker::PhantomData};

use crate::{
    rlc::{
        chip::RlcChip,
        circuit::builder::{RlcCircuitBuilder, RlcContextPair},
    },
    utils::component::{
        circuit::LoaderParamsPerComponentType,
        promise_loader::comp_loader::SingleComponentLoaderImpl,
    },
    Field,
};
use getset::{CopyGetters, Setters};
use halo2_base::{
    gates::GateInstructions,
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

use crate::utils::component::{
    circuit::{ComponentBuilder, PromiseBuilder},
    promise_collector::{PromiseCallsGetter, PromiseCommitSetter, PromiseResultsGetter},
    promise_loader::flatten_witness_to_rlc,
    types::{FixLenLogical, Flatten, LogicalEmpty},
    ComponentType, ComponentTypeId,
};

use super::comp_loader::{SingleComponentLoader, SingleComponentLoaderParams};

pub trait ComponentTypeList<F: Field> {
    fn get_component_type_ids() -> Vec<ComponentTypeId>;
    fn build_component_loaders(
        params_per_component: &HashMap<ComponentTypeId, SingleComponentLoaderParams>,
    ) -> Vec<Box<dyn SingleComponentLoader<F>>>;
}
pub struct ComponentTypeListEnd<F: Field> {
    _phantom: PhantomData<F>,
}
impl<F: Field> ComponentTypeList<F> for ComponentTypeListEnd<F> {
    fn get_component_type_ids() -> Vec<ComponentTypeId> {
        vec![]
    }
    fn build_component_loaders(
        _params_per_component: &HashMap<ComponentTypeId, SingleComponentLoaderParams>,
    ) -> Vec<Box<dyn SingleComponentLoader<F>>> {
        vec![]
    }
}
pub struct ComponentTypeListImpl<F: Field, HEAD: ComponentType<F>, LATER: ComponentTypeList<F>> {
    _phantom: PhantomData<(F, HEAD, LATER)>,
}
impl<F: Field, HEAD: ComponentType<F>, LATER: ComponentTypeList<F>> ComponentTypeList<F>
    for ComponentTypeListImpl<F, HEAD, LATER>
{
    fn get_component_type_ids() -> Vec<ComponentTypeId> {
        let mut ret = vec![HEAD::get_type_id()];
        ret.extend(LATER::get_component_type_ids());
        ret
    }
    fn build_component_loaders(
        params_per_component: &HashMap<ComponentTypeId, SingleComponentLoaderParams>,
    ) -> Vec<Box<dyn SingleComponentLoader<F>>> {
        type Loader<F, HEAD> = SingleComponentLoaderImpl<F, HEAD>;
        let mut ret = Vec::new();
        if let Some(params) = params_per_component.get(&HEAD::get_type_id()) {
            let comp_loader: Box<dyn SingleComponentLoader<F>> =
                Box::new(Loader::<F, HEAD>::new(params.clone()));
            ret.push(comp_loader);
        }
        ret.extend(LATER::build_component_loaders(params_per_component));
        ret
    }
}
#[macro_export]
macro_rules! component_type_list {
    ($field:ty, $comp_type:ty) => {
        $crate::utils::component::promise_loader::multi::ComponentTypeListImpl<$field, $comp_type, $crate::utils::component::promise_loader::multi::ComponentTypeListEnd<$field>>
    };
    ($field:ty, $comp_type:ty, $($comp_types:ty),+) => {
        $crate::utils::component::promise_loader::multi::ComponentTypeListImpl<$field, $comp_type, $crate::component_type_list!($field, $($comp_types),+)>
    }
}

#[derive(Clone)]
pub struct MultiPromiseLoaderConfig {
    pub dyn_lookup_config: BasicDynLookupConfig<1>,
}

// TODO: this is useless now because comp_loaders already have the information.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MultiPromiseLoaderParams {
    pub params_per_component: HashMap<ComponentTypeId, SingleComponentLoaderParams>,
}

/// Load promises of multiple component types which share the same lookup table.
/// The size of promise result it receives MUST match its capacity.
/// VT is a virtual component type which is used to generate lookup table. Its promise
/// results should not be fulfilled by external.
/// TODO: Currently we don't support promise calls for virtual component types so we enforce output to be empty.
/// TODO: remove virtual component type.
#[derive(CopyGetters, Setters)]
pub struct MultiPromiseLoader<
    F: Field,
    VT: ComponentType<F, OutputValue = LogicalEmpty<F>, OutputWitness = LogicalEmpty<AssignedValue<F>>>,
    CLIST: ComponentTypeList<F>,
    A: RlcAdapter<F>,
> {
    params: MultiPromiseLoaderParams,
    // ComponentTypeId -> (input, output)
    witness_promise_results: Option<
        HashMap<ComponentTypeId, Vec<(Flatten<AssignedValue<F>>, Flatten<AssignedValue<F>>)>>,
    >,
    // (to lookup, lookup table)
    witness_rlc_lookup: Option<(Vec<AssignedValue<F>>, Vec<AssignedValue<F>>)>,
    // A bit hacky..
    witness_gen_only: bool,
    copy_manager: Option<SharedCopyConstraintManager<F>>,
    pub(super) comp_loaders: Vec<Box<dyn SingleComponentLoader<F>>>,
    _phantom: PhantomData<(VT, CLIST, A)>,
}

pub trait RlcAdapter<F: Field> {
    fn to_rlc(
        ctx_pair: RlcContextPair<F>,
        gate: &impl GateInstructions<F>,
        rlc: &RlcChip<F>,
        type_id: &ComponentTypeId,
        io_pairs: &[(Flatten<AssignedValue<F>>, Flatten<AssignedValue<F>>)],
    ) -> Vec<AssignedValue<F>>;
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
    > ComponentBuilder<F> for MultiPromiseLoader<F, VT, CLIST, A>
{
    type Config = MultiPromiseLoaderConfig;
    type Params = MultiPromiseLoaderParams;

    /// Create MultiPromiseLoader
    fn new(params: MultiPromiseLoaderParams) -> Self {
        let comp_loaders = CLIST::build_component_loaders(&params.params_per_component);
        Self {
            params,
            witness_promise_results: None,
            witness_rlc_lookup: None,
            witness_gen_only: false,
            copy_manager: None,
            comp_loaders,
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

impl<
        F: Field,
        VT: ComponentType<
            F,
            OutputValue = LogicalEmpty<F>,
            OutputWitness = LogicalEmpty<AssignedValue<F>>,
        >,
        CLIST: ComponentTypeList<F>,
        A: RlcAdapter<F>,
    > PromiseBuilder<F> for MultiPromiseLoader<F, VT, CLIST, A>
{
    // NOTE: the actual dependencies are based on the params.
    fn get_component_type_dependencies() -> Vec<ComponentTypeId> {
        CLIST::get_component_type_ids()
    }
    fn extract_loader_params_per_component_type(
        params: &Self::Params,
    ) -> Vec<LoaderParamsPerComponentType> {
        let mut ret = Vec::new();
        for type_id in Self::get_component_type_dependencies() {
            if let Some(loader_params) = params.params_per_component.get(&type_id) {
                ret.push(LoaderParamsPerComponentType {
                    component_type_id: type_id,
                    loader_params: loader_params.clone(),
                })
            }
        }
        ret
    }
    fn fulfill_promise_results(&mut self, promise_results_getter: &impl PromiseResultsGetter<F>) {
        assert!(
            promise_results_getter.get_results_by_component_type_id(&VT::get_type_id()).is_none(),
            "promise results of the virtual component type should not be fulfilled"
        );
        for comp_loader in &mut self.comp_loaders {
            let component_type_id = comp_loader.get_component_type_id();
            let promise_results = promise_results_getter
                .get_results_by_component_type_id(&component_type_id)
                .unwrap_or_else(|| {
                    panic!("missing promise results for component type id {:?}", component_type_id)
                });

            comp_loader.load_promise_results(promise_results.clone());
        }
    }

    fn virtual_assign_phase0(
        &mut self,
        builder: &mut RlcCircuitBuilder<F>,
        promise_commit_setter: &mut impl PromiseCommitSetter<F>,
    ) {
        assert!(self.witness_promise_results.is_none());
        self.witness_gen_only = builder.witness_gen_only();

        let mut witness_promise_results = HashMap::new();

        for comp_loader in &self.comp_loaders {
            // TODO: Multi-thread here?
            let (commit, witness_promise_results_per_type) =
                comp_loader.assign_and_compute_commitment(builder);
            let component_type_id = comp_loader.get_component_type_id();
            promise_commit_setter
                .set_commit_by_component_type_id(component_type_id.clone(), commit);
            witness_promise_results.insert(component_type_id, witness_promise_results_per_type);
        }

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
        let range_chip = &builder.range_chip();
        let rlc_chip = builder.rlc_chip(&range_chip.gate);
        let (gate_ctx, rlc_ctx) = builder.rlc_ctx_pair();

        let input_multiplier =
            rlc_chip.rlc_pow_fixed(gate_ctx, &range_chip.gate, VT::OutputValue::get_num_fields());

        let component_type_id = VT::get_type_id();

        let calls_per_context =
            promise_calls_getter.get_calls_by_component_type_id(&component_type_id).unwrap();

        let to_lookup_rlc = calls_per_context
            .values()
            .flatten()
            .map(|(f_i, f_o)| {
                let i_rlc = f_i.to_rlc((gate_ctx, rlc_ctx), range_chip, &rlc_chip);
                let o_rlc = flatten_witness_to_rlc(rlc_ctx, &rlc_chip, f_o);
                range_chip.gate.mul_add(gate_ctx, i_rlc, input_multiplier, o_rlc)
            })
            .collect_vec();

        let num_dependencies = self.comp_loaders.len();
        let mut lookup_table_rlc = Vec::with_capacity(num_dependencies);

        // **Order must be deterministic.**
        for comp_loader in &self.comp_loaders {
            let component_type_id = comp_loader.get_component_type_id();
            let ctx_pair = (&mut *gate_ctx, &mut *rlc_ctx);
            let lookup_table_rlc_per_type = A::to_rlc(
                ctx_pair,
                &range_chip.gate,
                &rlc_chip,
                &component_type_id,
                &self.witness_promise_results.as_ref().unwrap()[&component_type_id],
            );
            lookup_table_rlc.push(lookup_table_rlc_per_type);
        }
        let lookup_table_rlc = lookup_table_rlc.concat();

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
                format!("promise loader adds advice to lookup for {}", VT::get_type_name())
            }),
            lookup_table.iter().map(|a| [*a; 1]),
            copy_manager,
        );

        dyn_lookup_config.assign_virtual_to_lookup_to_raw(
            layouter
                .namespace(|| format!("promise loader loads lookup table {}", VT::get_type_name())),
            to_lookup.iter().map(|a| [*a; 1]),
            copy_manager,
        );
    }
}

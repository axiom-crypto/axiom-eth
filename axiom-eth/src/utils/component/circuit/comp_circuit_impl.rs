use std::{
    any::Any,
    borrow::BorrowMut,
    cell::RefCell,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

#[cfg(feature = "aggregation")]
use crate::utils::build_utils::aggregation::CircuitMetadata;
use crate::{
    rlc::circuit::{builder::RlcCircuitBuilder, RlcCircuitParams, RlcConfig},
    rlc::virtual_region::RlcThreadBreakPoints,
    utils::{
        build_utils::pinning::{
            CircuitPinningInstructions, Halo2CircuitPinning, RlcCircuitPinning,
        },
        component::{
            circuit::{CoreBuilder, CoreBuilderOutput, PromiseBuilder},
            promise_collector::{PromiseCaller, PromiseCollector, SharedPromiseCollector},
            promise_loader::comp_loader::ComponentCommiter,
            types::ComponentPublicInstances,
            utils::create_hasher,
            ComponentCircuit, ComponentPromiseResultsInMerkle, ComponentType, ComponentTypeId,
            GroupedPromiseCalls, GroupedPromiseResults, LogicalInputValue, PromiseShardMetadata,
        },
        DEFAULT_RLC_CACHE_BITS,
    },
};
use anyhow::anyhow;
use halo2_base::{
    gates::{circuit::CircuitBuilderStage, GateChip},
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    virtual_region::manager::VirtualRegionManager,
    AssignedValue,
};
use itertools::Itertools;

use crate::Field;
#[cfg(feature = "aggregation")]
use snark_verifier_sdk::CircuitExt;

#[derive(Clone, Debug)]
pub struct ComponentCircuitImpl<F: Field, C: CoreBuilder<F>, P: PromiseBuilder<F>> {
    pub rlc_builder: RefCell<RlcCircuitBuilder<F>>,
    pub promise_collector: SharedPromiseCollector<F>,
    pub core_builder: RefCell<C>,
    pub promise_builder: RefCell<P>,
    pub val_public_instances: RefCell<Option<ComponentPublicInstances<F>>>,
}

impl<F: Field, C: CoreBuilder<F>, P: PromiseBuilder<F>> ComponentCircuitImpl<F, C, P> {
    /// Create a new component circuit.
    pub fn new(
        core_builder_params: C::Params,
        promise_builder_params: P::Params,
        prompt_rlc_params: RlcCircuitParams,
    ) -> Self {
        Self::new_impl(false, core_builder_params, promise_builder_params, prompt_rlc_params)
    }
    /// Create a new component circuit, with special prover-only optimizations
    /// when `witness_gen_only` is true.
    pub fn new_impl(
        witness_gen_only: bool,
        core_builder_params: C::Params,
        promise_builder_params: P::Params,
        prompt_rlc_params: RlcCircuitParams,
    ) -> Self {
        let stage =
            if witness_gen_only { CircuitBuilderStage::Prover } else { CircuitBuilderStage::Mock };
        Self::new_from_stage(stage, core_builder_params, promise_builder_params, prompt_rlc_params)
    }
    /// Create a new component circuit, with special prover-only optimizations
    /// when `witness_gen_only` is true. When `stage` is `Keygen`, `use_unknown`
    /// is set to true in [RlcCircuitBuilder], and `promise_collector` does not
    /// check promise results have been provided before fulfilling.
    pub fn new_from_stage(
        stage: CircuitBuilderStage,
        core_builder_params: C::Params,
        promise_builder_params: P::Params,
        prompt_rlc_params: RlcCircuitParams,
    ) -> Self {
        let mut rlc_builder = RlcCircuitBuilder::from_stage(stage, DEFAULT_RLC_CACHE_BITS)
            .use_params(prompt_rlc_params);
        // Public instances are fully managed by ComponentCircuitImpl.
        rlc_builder.base.set_instance_columns(1);
        Self {
            rlc_builder: RefCell::new(rlc_builder),
            promise_collector: Arc::new(Mutex::new(PromiseCollector::new(
                P::get_component_type_dependencies(),
            ))),
            core_builder: RefCell::new(C::new(core_builder_params)),
            promise_builder: RefCell::new(P::new(promise_builder_params)),
            val_public_instances: RefCell::new(None),
        }
    }
    pub fn use_break_points(self, break_points: RlcThreadBreakPoints) -> Self {
        self.rlc_builder.borrow_mut().set_break_points(break_points);
        self
    }
    pub fn prover(
        core_builder_params: C::Params,
        promise_builder_params: P::Params,
        prompt_rlc_pinning: RlcCircuitPinning,
    ) -> Self {
        Self::new_impl(true, core_builder_params, promise_builder_params, prompt_rlc_pinning.params)
            .use_break_points(prompt_rlc_pinning.break_points)
    }

    /// Calculate params. This should be called only after all promise results are fulfilled.
    pub fn calculate_params(&mut self) -> <ComponentCircuitImpl<F, C, P> as Circuit<F>>::Params {
        self.virtual_assign_phase0().expect("virtual assign phase0 failed");
        self.virtual_assign_phase1();

        let result = (
            self.core_builder.borrow_mut().calculate_params(),
            self.promise_builder.borrow_mut().calculate_params(),
            self.rlc_builder.borrow_mut().calculate_params(Some(9)),
        );

        // clear in case synthesize is called multiple times
        self.clear_witnesses();

        self.rlc_builder.borrow_mut().set_params(result.2.clone());

        result
    }

    pub fn virtual_assign_phase0(&self) -> Result<(), Error> {
        let mut borrowed_rlc_builder = self.rlc_builder.borrow_mut();
        let rlc_builder = borrowed_rlc_builder.deref_mut();

        let mut core_builder = self.core_builder.borrow_mut();
        let mut promise_builder = self.promise_builder.borrow_mut();

        {
            let mut borrowed_promise_collector = self.promise_collector.lock().unwrap();
            let promise_collector = borrowed_promise_collector.deref_mut();
            promise_builder.virtual_assign_phase0(rlc_builder, promise_collector);
        }

        let CoreBuilderOutput { public_instances: other_pis, virtual_table: vt, .. } = core_builder
            .virtual_assign_phase0(rlc_builder, PromiseCaller::new(self.promise_collector.clone()));
        let output_commit =
            <<C as CoreBuilder<F>>::CompType as ComponentType<F>>::Commiter::compute_commitment(
                &mut rlc_builder.base,
                &vt,
            );

        let mut borrowed_promise_collector = self.promise_collector.lock().unwrap();
        let promise_collector = borrowed_promise_collector.deref_mut();
        let public_instances = self.generate_public_instances(
            rlc_builder,
            promise_collector,
            &P::get_component_type_dependencies(),
            output_commit,
            other_pis,
        )?;

        let pis = rlc_builder.public_instances();
        pis[0] = public_instances.into();
        Ok(())
    }

    fn virtual_assign_phase1(&self) {
        let mut rlc_builder = self.rlc_builder.borrow_mut();

        // Load promise results first in case the core builder depends on them.
        {
            let mut promise_collector = self.promise_collector.lock().unwrap();
            self.promise_builder
                .borrow_mut()
                .virtual_assign_phase1(&mut rlc_builder, promise_collector.deref_mut());
        }
        self.core_builder.borrow_mut().virtual_assign_phase1(&mut rlc_builder);
    }

    fn generate_public_instances(
        &self,
        rlc_builder: &mut RlcCircuitBuilder<F>,
        promise_collector: &PromiseCollector<F>,
        dependencies: &[ComponentTypeId],
        output_commit: AssignedValue<F>,
        other_pis: Vec<AssignedValue<F>>,
    ) -> Result<ComponentPublicInstances<AssignedValue<F>>, Error> {
        let mut promise_commits = Vec::with_capacity(dependencies.len());
        for component_type_id in dependencies {
            if let Some(commit) =
                promise_collector.get_commit_by_component_type_id(component_type_id)
            {
                promise_commits.push(commit);
            }
        }
        let gate_chip = GateChip::new();

        let ctx = rlc_builder.base.main(0);
        let mut hasher = create_hasher::<F>();
        hasher.initialize_consts(ctx, &gate_chip);
        let promise_commit = hasher.hash_fix_len_array(ctx, &gate_chip, &promise_commits);

        let public_instances = ComponentPublicInstances::<AssignedValue<F>> {
            output_commit,
            promise_result_commit: promise_commit,
            other: other_pis,
        };
        if promise_collector.promise_results_ready() {
            *self.val_public_instances.borrow_mut() = Some(public_instances.clone().into());
        }
        Ok(public_instances)
    }
}

impl<F: Field, C: CoreBuilder<F>, P: PromiseBuilder<F>> ComponentCircuit<F>
    for ComponentCircuitImpl<F, C, P>
{
    fn clear_witnesses(&self) {
        self.rlc_builder.borrow_mut().clear();
        self.promise_collector.lock().unwrap().clear_witnesses();
        self.core_builder.borrow_mut().clear_witnesses();
        self.promise_builder.borrow_mut().clear_witnesses();
    }
    /// **Warning:** the returned deduped calls ordering is not deterministic.
    fn compute_promise_calls(&self) -> anyhow::Result<GroupedPromiseCalls> {
        let mut borrowed_rlc_builder = self.rlc_builder.borrow_mut();
        let rlc_builder = borrowed_rlc_builder.deref_mut();
        let mut borrowed_core_builder = self.core_builder.borrow_mut();
        let core_builder = borrowed_core_builder.deref_mut();

        core_builder
            .virtual_assign_phase0(rlc_builder, PromiseCaller::new(self.promise_collector.clone()));
        let mut borrowed_promise_collector = self.promise_collector.lock().unwrap();
        let deduped_calls = borrowed_promise_collector.get_deduped_calls();

        // clear in case synthesize is called multiple times
        core_builder.clear_witnesses();
        borrowed_promise_collector.clear_witnesses();
        rlc_builder.clear();

        Ok(deduped_calls)
    }

    /// Feed inputs into the core builder. The `input` type should be the `<C as CoreBuilder<F>::CoreInput` type.
    /// It is the caller's responsibility to ensure that the capacity of the input
    /// is equal to the configured capacity of the component circuit. This function
    /// does **not** check this.
    fn feed_input(&self, input: Box<dyn Any>) -> anyhow::Result<()> {
        let typed_input = input
            .as_ref()
            .downcast_ref::<<C as CoreBuilder<F>>::CoreInput>()
            .ok_or_else(|| anyhow!("invalid input type"))?
            .clone();
        self.core_builder.borrow_mut().feed_input(typed_input)?;
        Ok(())
    }

    fn fulfill_promise_results(
        &self,
        promise_results: &GroupedPromiseResults<F>,
    ) -> anyhow::Result<()> {
        let mut borrowed_promise_collector = self.promise_collector.lock().unwrap();
        let promise_collector = borrowed_promise_collector.deref_mut();
        promise_collector.fulfill(promise_results);

        self.promise_builder.borrow_mut().fulfill_promise_results(promise_collector);
        Ok(())
    }

    /// When inputs and promise results are ready, we can generate outputs of this component.
    ///
    /// Return logical outputs and the output commit of the virtual table. The output commit is calculated using the configured capacity in the params.
    /// But the returned metadata capacity is the true used capacity of the component based on the inputs, **not** the configured capacity.
    fn compute_outputs(&self) -> anyhow::Result<ComponentPromiseResultsInMerkle<F>> {
        self.promise_collector.lock().unwrap().set_promise_results_ready(true);

        let mut borrowed_rlc_builder = self.rlc_builder.borrow_mut();
        let rlc_builder = borrowed_rlc_builder.deref_mut();
        let mut borrowed_core_builder = self.core_builder.borrow_mut();
        let core_builder = borrowed_core_builder.deref_mut();

        let CoreBuilderOutput { virtual_table: vt, logical_results, .. } = core_builder
            .virtual_assign_phase0(rlc_builder, PromiseCaller::new(self.promise_collector.clone()));
        let capacity: usize = logical_results.iter().map(|lr| lr.input.get_capacity()).sum();

        let vt = vt.into_iter().map(|(v_i, v_o)| (v_i.into(), v_o.into())).collect_vec();
        let output_commit_val =
            <<C as CoreBuilder<F>>::CompType as ComponentType<F>>::Commiter::compute_native_commitment(
                &vt,
            );
        // Release RefCell for clear_witnesses later.
        drop(borrowed_rlc_builder);
        drop(borrowed_core_builder);
        self.clear_witnesses();

        Ok(ComponentPromiseResultsInMerkle::<F>::new(
            vec![PromiseShardMetadata { commit: output_commit_val, capacity }],
            vec![(0, logical_results.into_iter().map(|lr| lr.into()).collect())],
        ))
    }

    fn get_public_instances(&self) -> ComponentPublicInstances<F> {
        let has_pi_value = self.val_public_instances.borrow().is_some();
        if !has_pi_value {
            self.promise_collector.lock().unwrap().set_promise_results_ready(true);
            self.virtual_assign_phase0().unwrap();
            self.clear_witnesses();
        }
        self.val_public_instances.borrow().as_ref().unwrap().clone()
    }
}

impl<F: Field, C: CoreBuilder<F>, P: PromiseBuilder<F>> Circuit<F>
    for ComponentCircuitImpl<F, C, P>
{
    type Config = (C::Config, P::Config, RlcConfig<F>);
    type Params = (C::Params, P::Params, RlcCircuitParams);
    type FloorPlanner = SimpleFloorPlanner;

    fn params(&self) -> Self::Params {
        (
            self.core_builder.borrow().get_params(),
            self.promise_builder.borrow().get_params(),
            self.rlc_builder.borrow().params(),
        )
    }

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let k = params.2.base.k;
        let core_config = C::configure_with_params(meta, params.0);
        let mut rlc_config = RlcConfig::configure(meta, params.2);
        // There must be some phase 0 columns before creating phase 1 columns.
        let promise_config = P::configure_with_params(meta, params.1);
        // This is really tricky..
        let usable_rows = (1 << k) - meta.minimum_rows();
        rlc_config.set_usable_rows(usable_rows);
        (core_config, promise_config, rlc_config)
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!()
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // Promise results must be ready at this point, unless in Keygen mode.
        if !self.rlc_builder.borrow().base.core().use_unknown() {
            self.promise_collector.lock().unwrap().set_promise_results_ready(true);
        }
        config.2.base.initialize(&mut layouter);
        self.virtual_assign_phase0()?;
        {
            let mut core_builder = self.core_builder.borrow_mut();
            let mut promise_builder = self.promise_builder.borrow_mut();
            let mut rlc_builder = self.rlc_builder.borrow_mut();

            let mut phase0_layouter = layouter.namespace(|| "raw synthesize phase0");
            core_builder.borrow_mut().raw_synthesize_phase0(&config.0, &mut phase0_layouter);
            promise_builder.raw_synthesize_phase0(&config.1, &mut phase0_layouter);
            rlc_builder.raw_synthesize_phase0(&config.2, phase0_layouter);

            #[cfg(feature = "halo2-axiom")]
            {
                if rlc_builder.witness_gen_only() {
                    // To save memory, clear virtual columns in phase0 because they should never be used again
                    rlc_builder.base.pool(0).threads.clear();
                }
                drop(rlc_builder);
                layouter.next_phase();
            }
        }
        self.rlc_builder
            .borrow_mut()
            .load_challenge(&config.2, layouter.namespace(|| "load challenges"));

        self.virtual_assign_phase1();
        {
            let mut core_builder = self.core_builder.borrow_mut();
            let mut promise_builder = self.promise_builder.borrow_mut();
            let rlc_builder = self.rlc_builder.borrow();

            let mut phase1_layouter =
                layouter.namespace(|| "Core + RlcCircuitBuilder raw synthesize phase1");
            core_builder.raw_synthesize_phase1(&config.0, &mut phase1_layouter);
            rlc_builder.raw_synthesize_phase1(&config.2, phase1_layouter, false);
            promise_builder.raw_synthesize_phase1(&config.1, &mut layouter);
        }

        let rlc_builder = self.rlc_builder.borrow();
        if !rlc_builder.witness_gen_only() {
            layouter.assign_region(
                || "copy constraints",
                |mut region| {
                    let constant_cols = config.2.base.constants();
                    rlc_builder.copy_manager().assign_raw(constant_cols, &mut region);
                    Ok(())
                },
            )?;
        }
        drop(rlc_builder);

        // clear in case synthesize is called multiple times
        self.clear_witnesses();

        Ok(())
    }
}

// TODO: Maybe change?
impl<F: Field, C: CoreBuilder<F>, P: PromiseBuilder<F>> CircuitPinningInstructions
    for ComponentCircuitImpl<F, C, P>
{
    type Pinning = RlcCircuitPinning;
    fn pinning(&self) -> Self::Pinning {
        let break_points = self.rlc_builder.borrow().break_points();
        let params = self.rlc_builder.borrow().params();
        RlcCircuitPinning::new(params, break_points)
    }
}

#[cfg(feature = "aggregation")]
impl<F: Field, C: CoreBuilder<F>, P: PromiseBuilder<F>> CircuitExt<F>
    for ComponentCircuitImpl<F, C, P>
where
    C: CircuitMetadata,
{
    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        C::accumulator_indices()
    }

    fn instances(&self) -> Vec<Vec<F>> {
        let res = vec![self.get_public_instances().into()];
        res
    }

    fn num_instance(&self) -> Vec<usize> {
        vec![self.instances()[0].len()]
    }
}

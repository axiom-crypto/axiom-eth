use std::{
    cell::RefCell,
    collections::HashMap,
    fs::File,
    ops::DerefMut,
    path::Path,
    sync::{Arc, Mutex},
};

use crate::Field;
use halo2_base::{
    gates::circuit::CircuitBuilderStage,
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{self, Circuit, ConstraintSystem, SecondPhase},
    },
    virtual_region::{lookups::basic::BasicDynLookupConfig, manager::VirtualRegionManager},
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    keccak::{
        types::{ComponentTypeKeccak, KeccakLogicalInput, OutputKeccakShard},
        KeccakChip,
    },
    mpt::MPTChip,
    rlc::{
        circuit::{builder::RlcCircuitBuilder, RlcCircuitParams, RlcConfig},
        virtual_region::RlcThreadBreakPoints,
    },
    rlp::RlpChip,
    utils::{
        build_utils::pinning::{CircuitPinningInstructions, RlcCircuitPinning},
        component::{
            circuit::{ComponentBuilder, PromiseBuilder},
            promise_collector::{PromiseCaller, PromiseCollector, SharedPromiseCollector},
            promise_loader::single::{PromiseLoader, PromiseLoaderConfig, PromiseLoaderParams},
        },
        DEFAULT_RLC_CACHE_BITS,
    },
};

use super::{
    build_utils::pinning::Halo2CircuitPinning,
    component::{
        utils::try_from_key, ComponentPromiseResultsInMerkle, ComponentType, LogicalInputValue,
    },
};

/// Default number of lookup bits for range check is set to 8 for range checking bytes.
pub(crate) const ETH_LOOKUP_BITS: usize = 8;

/// Configuration parameters for [EthConfig]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthCircuitParams {
    pub rlc: RlcCircuitParams,
    /// Keccak promise loader
    pub keccak: PromiseLoaderParams,
}

impl Default for EthCircuitParams {
    fn default() -> Self {
        let mut rlc = RlcCircuitParams::default();
        rlc.base.num_instance_columns = 1;
        rlc.base.lookup_bits = Some(ETH_LOOKUP_BITS);
        let keccak = Default::default();
        Self { rlc, keccak }
    }
}

impl EthCircuitParams {
    pub fn new(rlc: RlcCircuitParams, keccak: PromiseLoaderParams) -> Self {
        Self { rlc, keccak }
    }
    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        serde_json::from_reader(File::open(&path).unwrap()).unwrap()
    }
    pub fn k(&self) -> usize {
        self.rlc.base.k
    }
    pub fn set_k(&mut self, k: usize) {
        self.rlc.base.k = k;
    }
}

/// Halo2 Config shared by all circuits that prove data about the Ethereum execution layer (EL).
/// Includes [BaseConfig] and [PureRlcConfig] inside [RlcConfig] that use Base + RLC + Keccak
#[derive(Clone)]
pub struct EthConfig<F: Field> {
    pub rlc_config: RlcConfig<F>,
    pub keccak: PromiseLoaderConfig,
}

impl<F: Field> EthConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, params: impl Into<EthCircuitParams>) -> Self {
        let params: EthCircuitParams = params.into();
        let k = params.k();
        let mut rlc_config = RlcConfig::configure(meta, params.rlc);
        // TODO: allow 0 columns here for more flexibility
        let keccak = PromiseLoaderConfig {
            dyn_lookup_config: BasicDynLookupConfig::new(meta, || SecondPhase, 1),
        };
        log::info!("Poisoned rows after EthConfig::configure {}", meta.minimum_rows());
        // Warning: this needs to be updated if you create more advice columns after this `EthConfig` is created
        let usable_rows = (1usize << k) - meta.minimum_rows();
        rlc_config.set_usable_rows(usable_rows);
        Self { rlc_config, keccak }
    }
}

/// Simple trait describing the FirstPhase and SecondPhase witness generation of a circuit
/// that only uses [EthConfig].
///
/// * In FirstPhase, [MPTChip] is provided with `None` for RlcChip.
/// * In SecondPhase, [MPTChip] is provided with RlcChip that has challenge value loaded.
pub trait EthCircuitInstructions<F: Field>: Clone {
    type FirstPhasePayload;

    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
    ) -> Self::FirstPhasePayload;

    /// SecondPhase is optional
    #[allow(unused_variables)]
    fn virtual_assign_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
        payload: Self::FirstPhasePayload,
    ) {
    }
}

/// This struct is used for the concrete implementation of [Circuit] trait from [EthCircuitInstructions].
/// This provides a quick way to create a circuit that only uses [EthConfig].
// This is basically a simplified version of `ComponentCircuitImpl` with `EthCircuitInstructions` + `PromiseLoader` for Keccak.
pub struct EthCircuitImpl<F: Field, I: EthCircuitInstructions<F>> {
    pub logic_inputs: I,
    pub keccak_chip: KeccakChip<F>,
    pub rlc_builder: RefCell<RlcCircuitBuilder<F>>,
    pub promise_collector: SharedPromiseCollector<F>,
    pub promise_builder: RefCell<PromiseLoader<F, ComponentTypeKeccak<F>>>,
    /// The FirstPhasePayload is set after FirstPhase witness generation.
    /// This is used both to pass payload between phases and also to detect if `virtual_assign_phase0`
    /// was already run outside of `synthesize` (e.g., to determine public instances)
    payload: RefCell<Option<I::FirstPhasePayload>>,
}

impl<F, I> EthCircuitImpl<F, I>
where
    F: Field,
    I: EthCircuitInstructions<F>,
{
    pub fn new(
        logic_inputs: I,
        prompt_rlc_params: RlcCircuitParams,
        promise_params: PromiseLoaderParams,
    ) -> Self {
        // Mock is general, can be used for anything
        Self::new_impl(CircuitBuilderStage::Mock, logic_inputs, prompt_rlc_params, promise_params)
    }
    pub fn new_impl(
        stage: CircuitBuilderStage,
        logic_inputs: I,
        prompt_rlc_params: RlcCircuitParams,
        promise_params: PromiseLoaderParams,
    ) -> Self {
        let rlc_builder = RlcCircuitBuilder::from_stage(stage, DEFAULT_RLC_CACHE_BITS)
            .use_params(prompt_rlc_params);
        let promise_loader = PromiseLoader::<F, ComponentTypeKeccak<F>>::new(promise_params);
        let promise_collector = Arc::new(Mutex::new(PromiseCollector::new(vec![
            ComponentTypeKeccak::<F>::get_type_id(),
        ])));
        let range = rlc_builder.range_chip();
        let keccak = KeccakChip::new_with_promise_collector(
            range,
            PromiseCaller::new(promise_collector.clone()),
        );
        Self {
            logic_inputs,
            keccak_chip: keccak,
            rlc_builder: RefCell::new(rlc_builder),
            promise_collector,
            promise_builder: RefCell::new(promise_loader),
            payload: RefCell::new(None),
        }
    }
    pub fn use_break_points(self, break_points: RlcThreadBreakPoints) -> Self {
        self.rlc_builder.borrow_mut().set_break_points(break_points);
        self
    }
    pub fn prover(
        logic_inputs: I,
        prompt_rlc_pinning: RlcCircuitPinning,
        promise_params: PromiseLoaderParams,
    ) -> Self {
        Self::new_impl(
            CircuitBuilderStage::Prover,
            logic_inputs,
            prompt_rlc_pinning.params,
            promise_params,
        )
        .use_break_points(prompt_rlc_pinning.break_points)
    }
    pub fn clear_witnesses(&self) {
        self.rlc_builder.borrow_mut().clear();
        self.promise_collector.lock().unwrap().clear_witnesses();
        self.payload.borrow_mut().take();
        self.promise_builder.borrow_mut().clear_witnesses();
    }

    /// FirstPhase witness generation with error handling.
    pub fn virtual_assign_phase0(&self) -> Result<(), plonk::Error> {
        if self.payload.borrow().is_some() {
            return Ok(());
        }
        let mut borrowed_rlc_builder = self.rlc_builder.borrow_mut();
        let rlc_builder = borrowed_rlc_builder.deref_mut();
        let mut promise_builder = self.promise_builder.borrow_mut();

        log::info!("EthCircuit: FirstPhase witness generation start");
        {
            let mut borrowed_promise_collector = self.promise_collector.lock().unwrap();
            let promise_collector = borrowed_promise_collector.deref_mut();
            promise_builder.virtual_assign_phase0(rlc_builder, promise_collector);
        }

        let rlp = RlpChip::new(self.keccak_chip.range(), None);
        let mpt = MPTChip::new(rlp, &self.keccak_chip);
        let payload = I::virtual_assign_phase0(&self.logic_inputs, rlc_builder, &mpt);
        self.payload.borrow_mut().replace(payload);
        // Add keccak promise as the last public instance in column 0:
        let promise_commit = self
            .promise_collector
            .lock()
            .unwrap()
            .get_commit_by_component_type_id(&ComponentTypeKeccak::<F>::get_type_id())
            .ok_or(plonk::Error::InvalidInstances)?;
        if rlc_builder.base.assigned_instances.is_empty() {
            return Err(plonk::Error::InvalidInstances);
        }
        rlc_builder.base.assigned_instances[0].push(promise_commit);
        log::info!("EthCircuit: FirstPhase witness generation complete");
        Ok(())
    }

    pub fn virtual_assign_phase1(&self) {
        let payload =
            self.payload.borrow_mut().take().expect("FirstPhase witness generation was not run");
        log::info!("EthCircuit: SecondPhase witness generation start");
        let mut rlc_builder = self.rlc_builder.borrow_mut();
        let range_chip = self.keccak_chip.range();
        let rlc_chip = rlc_builder.rlc_chip(&range_chip.gate);
        let rlp = RlpChip::new(range_chip, Some(&rlc_chip));
        let mpt = MPTChip::new(rlp, &self.keccak_chip);
        {
            let mut promise_collector = self.promise_collector.lock().unwrap();
            self.promise_builder
                .borrow_mut()
                .virtual_assign_phase1(&mut rlc_builder, promise_collector.deref_mut());
        }
        I::virtual_assign_phase1(&self.logic_inputs, &mut rlc_builder, &mpt, payload);
        log::info!("EthCircuit: SecondPhase witness generation complete");
    }

    pub fn fulfill_keccak_promise_results(
        &self,
        keccak_promise_results: ComponentPromiseResultsInMerkle<F>,
    ) -> Result<(), anyhow::Error> {
        let mut borrowed_promise_collector = self.promise_collector.lock().unwrap();
        let promise_collector = borrowed_promise_collector.deref_mut();
        promise_collector.fulfill(&HashMap::from_iter([(
            ComponentTypeKeccak::<F>::get_type_id(),
            keccak_promise_results,
        )]));
        self.promise_builder.borrow_mut().fulfill_promise_results(promise_collector);
        Ok(())
    }

    /// Calculate params. This should be called only after all promise results are fulfilled.
    pub fn calculate_params(&mut self) -> EthCircuitParams {
        self.virtual_assign_phase0().expect("virtual assign phase0 failed");
        self.virtual_assign_phase1();

        let rlc_params = self.rlc_builder.borrow_mut().calculate_params(Some(20));
        let promise_params = self.promise_builder.borrow_mut().calculate_params();

        self.clear_witnesses();

        EthCircuitParams { rlc: rlc_params, keccak: promise_params }
    }

    pub fn break_points(&self) -> RlcThreadBreakPoints {
        self.rlc_builder.borrow().break_points()
    }
    pub fn set_break_points(&self, break_points: RlcThreadBreakPoints) {
        self.rlc_builder.borrow_mut().set_break_points(break_points);
    }

    /// For testing only. A helper function to fulfill keccak promises for this circuit.
    pub fn mock_fulfill_keccak_promises(&self, capacity: Option<usize>) {
        let rlp = RlpChip::new(self.keccak_chip.range(), None);
        let mpt = MPTChip::new(rlp, &self.keccak_chip);
        I::virtual_assign_phase0(&self.logic_inputs, &mut self.rlc_builder.borrow_mut(), &mpt);
        let calls = self.promise_collector.lock().unwrap().get_deduped_calls();
        let keccak_calls = &calls[&ComponentTypeKeccak::<F>::get_type_id()];
        let mut used_capacity = 0;
        let responses = keccak_calls
            .iter()
            .map(|call| {
                let li = try_from_key::<KeccakLogicalInput>(&call.logical_input).unwrap();
                used_capacity += <KeccakLogicalInput as LogicalInputValue<F>>::get_capacity(&li);
                (li.bytes.clone().into(), None)
            })
            .collect_vec();

        let capacity = if let Some(capacity) = capacity { capacity } else { used_capacity };
        let output_shard = OutputKeccakShard { responses, capacity };
        self.fulfill_keccak_promise_results(ComponentPromiseResultsInMerkle::from_single_shard(
            output_shard.into_logical_results(),
        ))
        .unwrap();
        self.clear_witnesses();
    }

    pub fn instances(&self) -> Vec<Vec<F>> {
        self.virtual_assign_phase0().unwrap();
        let builder = self.rlc_builder.borrow();
        builder
            .base
            .assigned_instances
            .iter()
            .map(|instance| instance.iter().map(|x| *x.value()).collect())
            .collect()
    }
}

impl<F, I> Circuit<F> for EthCircuitImpl<F, I>
where
    F: Field,
    I: EthCircuitInstructions<F>,
{
    type FloorPlanner = SimpleFloorPlanner;
    type Config = EthConfig<F>;
    type Params = EthCircuitParams;

    fn params(&self) -> Self::Params {
        let rlc = self.rlc_builder.borrow().params();
        let keccak = self.promise_builder.borrow().get_params();
        EthCircuitParams { rlc, keccak }
    }

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        EthConfig::configure(meta, params)
    }
    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!()
    }

    // Mostly copied from ComponentCircuitImpl
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), plonk::Error> {
        self.promise_collector.lock().unwrap().set_promise_results_ready(true);
        config.rlc_config.base.initialize(&mut layouter);
        self.virtual_assign_phase0()?;
        {
            let mut promise_builder = self.promise_builder.borrow_mut();
            let rlc_builder = self.rlc_builder.borrow();

            let mut phase0_layouter = layouter.namespace(|| "raw synthesize phase0");
            promise_builder.raw_synthesize_phase0(&config.keccak, &mut phase0_layouter);
            rlc_builder.raw_synthesize_phase0(&config.rlc_config, phase0_layouter);
        }
        #[cfg(feature = "halo2-axiom")]
        {
            layouter.next_phase();
        }
        self.rlc_builder
            .borrow_mut()
            .load_challenge(&config.rlc_config, layouter.namespace(|| "load challenges"));

        self.virtual_assign_phase1();

        {
            let rlc_builder = self.rlc_builder.borrow();
            let phase1_layouter = layouter.namespace(|| "RlcCircuitBuilder raw synthesize phase1");
            rlc_builder.raw_synthesize_phase1(&config.rlc_config, phase1_layouter, false);

            let mut promise_builder = self.promise_builder.borrow_mut();
            promise_builder.raw_synthesize_phase1(&config.keccak, &mut layouter);
        }

        let rlc_builder = self.rlc_builder.borrow();
        if !rlc_builder.witness_gen_only() {
            layouter.assign_region(
                || "copy constraints",
                |mut region| {
                    let constant_cols = config.rlc_config.base.constants();
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

impl<F, I> CircuitPinningInstructions for EthCircuitImpl<F, I>
where
    F: Field,
    I: EthCircuitInstructions<F>,
{
    type Pinning = RlcCircuitPinning;
    fn pinning(&self) -> Self::Pinning {
        let break_points = self.break_points();
        let params = self.rlc_builder.borrow().params();
        RlcCircuitPinning::new(params, break_points)
    }
}

#[cfg(feature = "aggregation")]
mod aggregation {
    use crate::Field;
    use snark_verifier_sdk::CircuitExt;

    use crate::utils::build_utils::aggregation::CircuitMetadata;

    use super::{EthCircuitImpl, EthCircuitInstructions};

    impl<F, I> CircuitExt<F> for EthCircuitImpl<F, I>
    where
        F: Field,
        I: EthCircuitInstructions<F> + CircuitMetadata,
    {
        fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
            I::accumulator_indices()
        }

        fn instances(&self) -> Vec<Vec<F>> {
            self.instances()
        }

        fn num_instance(&self) -> Vec<usize> {
            self.logic_inputs.num_instance()
        }
    }
}

// ==== convenience functions for testing & benchmarking ====

pub fn create_circuit<F: Field, I: EthCircuitInstructions<F>>(
    stage: CircuitBuilderStage,
    circuit_params: RlcCircuitParams,
    logic_inputs: I,
) -> EthCircuitImpl<F, I> {
    EthCircuitImpl::new_impl(stage, logic_inputs, circuit_params, Default::default())
}

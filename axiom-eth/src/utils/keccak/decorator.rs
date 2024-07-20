//! A `Circuit` implementation for `EthCircuitInstructions` that consists of a circuit with both `RlcCircuitBuilder` and `KeccakComponentShardCircuit` as sub-circuits.
//! This is a complete circuit that can be used when keccak computations are necessary.
//! This circuit is **not** part of the Component Framework, so it does not have any additional dependencies or verification assumptions.

// @dev We still use the `ComponentType` and `ComponentLoader` trait to share as much code as possible with the Keccak promise loader implementation.

use std::{
    cell::RefCell,
    iter::{self, zip},
    mem,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use ethers_core::{types::H256, utils::keccak256};
use halo2_base::{
    gates::{
        circuit::CircuitBuilderStage,
        flex_gate::threads::{parallelize_core, SinglePhaseCoreManager},
        GateInstructions, RangeChip,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{self, Circuit, ConstraintSystem},
    },
    safe_types::SafeTypeChip,
    AssignedValue,
    QuantumCell::Constant,
};
use itertools::{zip_eq, Itertools};
use serde::{Deserialize, Serialize};
use zkevm_hashes::keccak::{
    component::{
        circuit::shard::{
            pack_inputs_from_keccak_fs, transmute_keccak_assigned_to_virtual, LoadedKeccakF,
        },
        encode::format_input,
    },
    vanilla::{
        keccak_packed_multi::get_num_keccak_f, witness::multi_keccak, KeccakAssignedRow,
        KeccakCircuitConfig, KeccakConfigParams,
    },
};

use crate::{
    keccak::{
        promise::{KeccakFixLenCall, KeccakVarLenCall},
        types::{ComponentTypeKeccak, KeccakVirtualInput, KeccakVirtualOutput},
        KeccakChip,
    },
    mpt::MPTChip,
    rlc::{
        circuit::{builder::RlcCircuitBuilder, RlcCircuitParams, RlcConfig},
        virtual_region::RlcThreadBreakPoints,
    },
    rlp::RlpChip,
    utils::{
        component::{
            promise_collector::{PromiseCaller, PromiseCallsGetter, PromiseCollector},
            ComponentType,
        },
        constrain_vec_equal, encode_h256_to_hilo, enforce_conditional_equality,
        eth_circuit::EthCircuitInstructions,
        hilo::HiLo,
        keccak::get_keccak_unusable_rows_from_capacity,
        DEFAULT_RLC_CACHE_BITS,
    },
    Field,
};

/// Configuration parameters for [RlcKeccakConfig]
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct RlcKeccakCircuitParams {
    /// RLC circuit parameters
    pub rlc: RlcCircuitParams,
    /// The number of rows per round of keccak_f in the keccak circuit.
    /// No `capacity` is needed because this circuit will do exactly the number of keccaks
    /// needed by the instructions. The `keccak_rows_per_round` must be small enough so that the
    /// circuit can performs all necessary keccaks, otherwise you will get a `NotEnoughRows` error.
    pub keccak_rows_per_round: usize,
}

impl RlcKeccakCircuitParams {
    pub fn new(rlc: RlcCircuitParams, keccak_rows_per_round: usize) -> Self {
        Self { rlc, keccak_rows_per_round }
    }
    pub fn k(&self) -> usize {
        self.rlc.base.k
    }
    pub fn set_k(&mut self, k: usize) {
        self.rlc.base.k = k;
    }
    pub fn use_k(mut self, k: usize) -> Self {
        self.rlc.base.k = k;
        self
    }
}

/// Halo2 Config that is a combination of [RlcConfig] and vanilla [KeccakCircuitConfig]
#[derive(Clone, Debug)]
pub struct RlcKeccakConfig<F: Field> {
    pub rlc: RlcConfig<F>,
    pub keccak: KeccakCircuitConfig<F>,
}

impl<F: Field> RlcKeccakConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, params: RlcKeccakCircuitParams) -> Self {
        let k = params.k();
        let mut rlc_config = RlcConfig::configure(meta, params.rlc);
        let keccak_config = KeccakCircuitConfig::new(
            meta,
            KeccakConfigParams { k: k as u32, rows_per_round: params.keccak_rows_per_round },
        );
        log::info!("Poisoned rows after RlcKeccakConfig::configure {}", meta.minimum_rows());
        // Warning: minimum_rows may have changed between RlcConfig::configure and now:
        let usable_rows = (1usize << k) - meta.minimum_rows();
        rlc_config.set_usable_rows(usable_rows);
        Self { rlc: rlc_config, keccak: keccak_config }
    }
}

/// This struct is used for the concrete implementation of [Circuit] trait from [EthCircuitInstructions] *which has a vanilla zkEVM keccak sub-circuit embedded* in the full circuit.
/// The difference between this and [EthCircuitImpl] is that this circuit is self-contained: it does not rely on any promise calls. All keccak computations will be fully proved when
/// this circuit is verified.
pub struct RlcKeccakCircuitImpl<F: Field, I: EthCircuitInstructions<F>> {
    pub logic_inputs: I,
    /// RLC Circuit Builder
    pub rlc_builder: RefCell<RlcCircuitBuilder<F>>,
    /// This is a passthrough to `SharedPromiseCollector` that contains the
    /// keccak functions. It collects the keccaks that needs to be done and handles
    /// some formatting. The actual keccaks will be passed on to the vanilla zkevm keccak
    /// sub-circuit to be proved.
    pub keccak_chip: KeccakChip<F>,
    pub keccak_rows_per_round: usize,
    /// The FirstPhasePayload is set after FirstPhase witness generation.
    /// This is used both to pass payload between phases and also to detect if `virtual_assign_phase0_start`
    /// was already run outside of `synthesize` (e.g., to determine public instances)
    pub payload: RefCell<Option<I::FirstPhasePayload>>,

    // we keep these as RefCell to pass between phases just so the user doesn't need to keep track of them:
    pub call_collector: RefCell<KeccakCallCollector<F>>,
}

impl<F, I> RlcKeccakCircuitImpl<F, I>
where
    F: Field,
    I: EthCircuitInstructions<F>,
{
    pub fn new(logic_inputs: I, circuit_params: RlcKeccakCircuitParams) -> Self {
        // Mock is general, can be used for anything
        Self::new_impl(
            CircuitBuilderStage::Mock,
            logic_inputs,
            circuit_params,
            DEFAULT_RLC_CACHE_BITS,
        )
    }
    /// When `RlcChip` is automatically constructed in `virtual_assign_phase1`, it will
    /// compute `gamma^{2^i}` for `i = 0..max_rlc_cache_bits`. This cache is used by
    /// RlpChip. Usually one should just set this to [DEFAULT_RLC_CACHE_BITS] to cover
    /// all possible use cases, since the cache computation cost is low.
    ///
    /// However we provide the option to set this to `0` because the Keccak decorator
    /// does not actually need RlcChip. Therefore if you only use `BaseCircuitBuilder` and
    /// KeccakChip and never use RlcChip, then setting this to `0` will mean that you do not
    /// create any unnecessary RLC advice columns.
    pub fn new_impl(
        stage: CircuitBuilderStage,
        logic_inputs: I,
        circuit_params: RlcKeccakCircuitParams,
        max_rlc_cache_bits: usize,
    ) -> Self {
        let rlc_builder =
            RlcCircuitBuilder::from_stage(stage, max_rlc_cache_bits).use_params(circuit_params.rlc);
        // We re-use this to save code and also because `KeccakChip` needs it in its constructor
        let promise_collector = Arc::new(Mutex::new(PromiseCollector::new(vec![
            ComponentTypeKeccak::<F>::get_type_id(),
        ])));
        let range = rlc_builder.range_chip();
        let keccak =
            KeccakChip::new_with_promise_collector(range, PromiseCaller::new(promise_collector));
        Self {
            logic_inputs,
            keccak_chip: keccak,
            keccak_rows_per_round: circuit_params.keccak_rows_per_round,
            rlc_builder: RefCell::new(rlc_builder),
            payload: RefCell::new(None),
            call_collector: Default::default(),
        }
    }
    pub fn use_break_points(self, break_points: RlcThreadBreakPoints) -> Self {
        self.rlc_builder.borrow_mut().set_break_points(break_points);
        self
    }
    /// Resets entire circuit state. Does not change original inputs.
    pub fn clear(&self) {
        self.rlc_builder.borrow_mut().clear();
        self.keccak_chip.promise_caller().0.lock().unwrap().clear_witnesses();
        self.payload.borrow_mut().take();
        self.call_collector.borrow_mut().clear();
    }

    /// FirstPhase witness generation with error handling.
    pub fn virtual_assign_phase0_start(&self) {
        if self.payload.borrow().is_some() {
            // We've already done phase0, perhaps outside of synthesize
            return;
        }
        #[cfg(feature = "display")]
        let start = std::time::Instant::now();
        let mut rlc_builder_ref = self.rlc_builder.borrow_mut();
        let rlc_builder = &mut rlc_builder_ref;

        let rlp = RlpChip::new(self.keccak_chip.range(), None);
        let mpt = MPTChip::new(rlp, &self.keccak_chip);
        // main instructions phase0
        let payload = I::virtual_assign_phase0(&self.logic_inputs, rlc_builder, &mpt);
        self.payload.borrow_mut().replace(payload);

        // now the KeccakChip promise_collector has all of the keccak (input, outputs) that need to be proven & constrained.
        let collector_guard = self.keccak_chip.promise_caller().0.lock().unwrap();
        let mut calls = self.call_collector.borrow_mut();
        assert!(calls.fix_len_calls.is_empty());
        assert!(calls.var_len_calls.is_empty());
        // these are the keccak inputs, outputs as virtual assigned cells
        // need to do some rust downcasting from PromiseCallWitness to either KeccakFixLenCall or KeccakVarLenCall
        for (input, output) in collector_guard
            .get_calls_by_component_type_id(&ComponentTypeKeccak::<F>::get_type_id())
            .unwrap()
            .values()
            .flatten()
        {
            if let Some(fix_len_call) = input.as_any().downcast_ref::<KeccakFixLenCall<F>>() {
                calls
                    .fix_len_calls
                    .push((fix_len_call.clone(), output.clone().try_into().unwrap()));
            } else if let Some(var_len_call) = input.as_any().downcast_ref::<KeccakVarLenCall<F>>()
            {
                calls
                    .var_len_calls
                    .push((var_len_call.clone(), output.clone().try_into().unwrap()));
            } else {
                unreachable!("KeccakChip should only use KeccakFixLenCall or KeccakVarLenCall");
            }
        }
        #[cfg(feature = "display")]
        log::info!("RlcKeccackCircuit virtual_assign_phase0_start time: {:?}", start.elapsed());
    }

    pub fn virtual_assign_phase1(&self) {
        let payload =
            self.payload.borrow_mut().take().expect("FirstPhase witness generation was not run");
        let mut rlc_builder = self.rlc_builder.borrow_mut();
        let range_chip = self.keccak_chip.range();
        // Note: this uses rlc columns to load RLC cache. Set `max_rlc_cache_bits = 0` in the `new_impl` constructor to disable this.
        let rlc_chip = rlc_builder.rlc_chip(&range_chip.gate);
        let rlp = RlpChip::new(range_chip, Some(&rlc_chip));
        let mpt = MPTChip::new(rlp, &self.keccak_chip);
        I::virtual_assign_phase1(&self.logic_inputs, &mut rlc_builder, &mpt, payload);
    }

    /// Calculate params. This should be called only after all promise results are fulfilled.
    pub fn calculate_params(&mut self) {
        self.virtual_assign_phase0_start();
        let mut capacity = 0;
        for (call, _) in self.call_collector.borrow().fix_len_calls.iter() {
            capacity += get_num_keccak_f(call.bytes().len());
        }
        for (call, _) in self.call_collector.borrow().var_len_calls.iter() {
            capacity += get_num_keccak_f(call.bytes().max_len());
        }
        // make mock loaded_keccak_fs just to simulate
        let copy_manager_ref = self.rlc_builder.borrow().copy_manager().clone();
        let mut copy_manager = copy_manager_ref.lock().unwrap();
        let virtual_keccak_fs = (0..capacity)
            .map(|_| {
                LoadedKeccakF::new(
                    copy_manager.mock_external_assigned(F::ZERO),
                    core::array::from_fn(|_| copy_manager.mock_external_assigned(F::ZERO)),
                    SafeTypeChip::unsafe_to_bool(copy_manager.mock_external_assigned(F::ZERO)),
                    copy_manager.mock_external_assigned(F::ZERO),
                    copy_manager.mock_external_assigned(F::ZERO),
                )
            })
            .collect_vec();
        drop(copy_manager);
        let keccak_calls = mem::take(self.call_collector.borrow_mut().deref_mut());
        keccak_calls.pack_and_constrain(
            virtual_keccak_fs,
            self.rlc_builder.borrow_mut().base.pool(0),
            self.keccak_chip.range(),
        );
        self.virtual_assign_phase1();

        let k = self.params().k();
        let (unusable_rows, rows_per_round) = get_keccak_unusable_rows_from_capacity(k, capacity);
        self.rlc_builder.borrow_mut().calculate_params(Some(unusable_rows));
        log::debug!("RlcKeccakCircuit used capacity: {capacity}");
        log::debug!("RlcKeccakCircuit optimal rows_per_round : {rows_per_round}");
        self.keccak_rows_per_round = rows_per_round;

        self.clear();
    }

    pub fn break_points(&self) -> RlcThreadBreakPoints {
        self.rlc_builder.borrow().break_points()
    }
    pub fn set_break_points(&self, break_points: RlcThreadBreakPoints) {
        self.rlc_builder.borrow_mut().set_break_points(break_points);
    }

    pub fn instances(&self) -> Vec<Vec<F>> {
        self.virtual_assign_phase0_start();
        let builder = self.rlc_builder.borrow();
        builder
            .base
            .assigned_instances
            .iter()
            .map(|instance| instance.iter().map(|x| *x.value()).collect())
            .collect()
    }
}

impl<F, I> Circuit<F> for RlcKeccakCircuitImpl<F, I>
where
    F: Field,
    I: EthCircuitInstructions<F>,
{
    type FloorPlanner = SimpleFloorPlanner;
    type Config = RlcKeccakConfig<F>;
    type Params = RlcKeccakCircuitParams;

    fn params(&self) -> Self::Params {
        let rlc = self.rlc_builder.borrow().params();
        let keccak_rows_per_round = self.keccak_rows_per_round;
        RlcKeccakCircuitParams { rlc, keccak_rows_per_round }
    }
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        RlcKeccakConfig::configure(meta, params)
    }
    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!()
    }

    /// This is organized to match `EthCircuitImpl::synthesize` as closely as possible, except that PromiseLoader is replaced with an actual vanilla keccak sub-circuit.
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), plonk::Error> {
        let RlcKeccakCircuitParams { rlc: rlc_circuit_params, keccak_rows_per_round } =
            self.params();
        let k = rlc_circuit_params.base.k;
        let keccak_circuit_params =
            KeccakConfigParams { k: k as u32, rows_per_round: keccak_rows_per_round };

        #[cfg(feature = "display")]
        let start = std::time::Instant::now();
        log::info!("RlcKeccakCircuit: phase0 start");
        config.rlc.base.initialize(&mut layouter);
        config.keccak.load_aux_tables(&mut layouter, k as u32)?;

        self.virtual_assign_phase0_start();
        let keccak_calls = mem::take(self.call_collector.borrow_mut().deref_mut());
        keccak_calls.assign_raw_and_constrain(
            keccak_circuit_params,
            &config.keccak,
            &mut layouter.namespace(|| "keccak sub-circuit"),
            self.rlc_builder.borrow_mut().base.pool(0),
            self.keccak_chip.range(),
        )?;

        // raw assign everything in RlcCircuitBuilder phase0, *including* the keccak virtual table (this is important because we will RLC the table in phase1).
        self.rlc_builder.borrow().raw_synthesize_phase0(
            &config.rlc,
            layouter.namespace(|| "RlcCircuitBuilder raw synthesize phase0"),
        );
        log::info!("RlcKeccakCircuit: phase0 end");
        #[cfg(feature = "display")]
        log::info!("RlcKeccakCircuit phase0 synthesize time: {:?}", start.elapsed());

        #[cfg(feature = "halo2-axiom")]
        layouter.next_phase();

        self.rlc_builder
            .borrow_mut()
            .load_challenge(&config.rlc, layouter.namespace(|| "load challenges"));

        self.virtual_assign_phase1();

        self.rlc_builder.borrow_mut().raw_synthesize_phase1(
            &config.rlc,
            layouter.namespace(|| "RlcCircuitBuilder raw synthesize phase1 + copy constraints"),
            true,
        );

        // clear in case synthesize is called multiple times
        self.clear();

        Ok(())
    }
}

#[derive(Clone, Default, Debug)]
pub struct KeccakCallCollector<F: Field> {
    pub fix_len_calls: Vec<(KeccakFixLenCall<F>, HiLo<AssignedValue<F>>)>,
    pub var_len_calls: Vec<(KeccakVarLenCall<F>, HiLo<AssignedValue<F>>)>,
}

impl<F: Field> KeccakCallCollector<F> {
    pub fn new(
        fix_len_calls: Vec<(KeccakFixLenCall<F>, HiLo<AssignedValue<F>>)>,
        var_len_calls: Vec<(KeccakVarLenCall<F>, HiLo<AssignedValue<F>>)>,
    ) -> Self {
        Self { fix_len_calls, var_len_calls }
    }

    pub fn clear(&mut self) {
        self.fix_len_calls.clear();
        self.var_len_calls.clear();
    }

    /// Format the KeccakFixLenCall's and KeccakVarLenCall's into
    /// variable length bytes as inputs to zkEVM keccak so that the
    /// keccak table from the keccak sub-circuit will exactly match
    /// the ordering and packing of the calls.
    pub fn format_keccak_inputs(&self) -> Vec<Vec<u8>> {
        let fix_len_calls = &self.fix_len_calls;
        let fix_len_calls = fix_len_calls.iter().map(|(call, _)| call.to_logical_input().bytes);
        let var_len_calls = &self.var_len_calls;
        let var_len_calls = var_len_calls.iter().flat_map(|(call, _)| {
            let capacity = get_num_keccak_f(call.bytes().max_len());
            let bytes = call.to_logical_input().bytes;
            // we need to pad with empty [] inputs so that we use exactly the same number of keccak_f as if we were computing keccak on a max_len input
            let used_capacity = get_num_keccak_f(bytes.len());
            iter::once(bytes).chain(iter::repeat(vec![]).take(capacity - used_capacity))
        });
        iter::empty().chain(fix_len_calls).chain(var_len_calls).collect()
    }

    /// Packs the loaded keccak_f rows and constrains that they exactly
    /// match the packing from the KeccakFixLenCall's and KeccakVarLenCall's.
    /// Needs to be done after raw synthesize of keccak sub-circuit.
    ///
    /// ## Assumptions
    /// - The `virtual_keccak_fs` should exactly correspond to the inputs generated by `format_keccak_inputs`.
    /// - `range_chip` should share same reference to `copy_manager` as `pool`.
    pub fn pack_and_constrain(
        self,
        virtual_keccak_fs: Vec<LoadedKeccakF<F>>,
        pool: &mut SinglePhaseCoreManager<F>,
        range_chip: &RangeChip<F>,
    ) {
        // We now pack the virtual cells into a virtual table using fewer field elements
        let gate = &range_chip.gate;
        let packed_inputs = pack_inputs_from_keccak_fs(pool.main(), gate, &virtual_keccak_fs);
        // Return the virtual table of inputs and outputs:
        let virtual_table = zip_eq(packed_inputs, virtual_keccak_fs).map(|(chunk, keccak_f)| {
            let v_i = KeccakVirtualInput::new(
                chunk.inputs().concat().try_into().unwrap(),
                chunk.is_final().into(),
            );
            let hash = HiLo::from_hi_lo([keccak_f.hash_hi(), keccak_f.hash_lo()]);
            let v_o = KeccakVirtualOutput::new(hash);
            (v_i, v_o)
        });

        // We also pack the `calls` in exactly the same way:
        let Self { fix_len_calls, var_len_calls } = self;
        // flat map fix_len_calls into virtual table, for each call since it's fixed len, we set is_final to true only on the last chunk
        let fix_len_vt = parallelize_core(pool, fix_len_calls, |ctx, (call, hash)| {
            let len = ctx.load_constant(F::from(call.bytes().len() as u64));
            let packed_input = format_input(ctx, gate, call.bytes().bytes(), len);
            let capacity = packed_input.len();
            packed_input
                .into_iter()
                .enumerate()
                .map(|(i, chunk)| {
                    let is_final = ctx.load_constant(F::from(i == capacity - 1));
                    let v_i = KeccakVirtualInput::new(chunk.concat().try_into().unwrap(), is_final);
                    // we mask this with is_final later
                    let v_o = KeccakVirtualOutput::new(hash);
                    (v_i, v_o)
                })
                .collect_vec()
        })
        .into_iter()
        .flatten();
        let empty_hash = encode_h256_to_hilo::<F>(&H256(keccak256([])));
        // flat map fix_len_calls into virtual table
        let var_len_vt = parallelize_core(pool, var_len_calls, |ctx, (call, hash)| {
            let num_keccak_f_m1 = call.num_keccak_f_m1(ctx, range_chip);
            // `ensure_0_padding` so that `packed_input` after variable length `bytes.len()` corresponds to format_input of [] empty bytes
            let bytes = call.bytes().ensure_0_padding(ctx, gate);
            let packed_input = format_input(ctx, gate, bytes.bytes(), *bytes.len());
            // since a call is variable_length, we need to set is_final to be 0, 0, ..., 0, 1, 1, ... where the first 1 is at `num_keccak_f - 1`
            let capacity = get_num_keccak_f(call.bytes().max_len());
            assert_eq!(capacity, packed_input.len());
            // we have constrained that `num_keccak_f - 1 < capacity`
            let indicator = gate.idx_to_indicator(ctx, num_keccak_f_m1, capacity);
            let is_finals = gate.partial_sums(ctx, indicator.clone()).collect_vec();
            zip(packed_input, zip_eq(is_finals, indicator))
                .map(|(chunk, (is_final, is_out))| {
                    // We pad with empty hashes keccak([]) between the true capacity and the max capacity for each var len call
                    let v_i = KeccakVirtualInput::new(chunk.concat().try_into().unwrap(), is_final);
                    // If we beyond the true capacity, then we need the hash output to be empty hash
                    // We will later mask hash with is_final as well
                    let hash_hi = gate.select(ctx, hash.hi(), Constant(empty_hash.hi()), is_out);
                    let hash_lo = gate.select(ctx, hash.lo(), Constant(empty_hash.lo()), is_out);
                    let v_o = KeccakVirtualOutput::new(HiLo::from_hi_lo([hash_hi, hash_lo]));
                    (v_i, v_o)
                })
                .collect_vec()
        })
        .into_iter()
        .flatten();

        // now we compare the virtual table from the vanilla keccak circuit with the virtual table constructed from the calls. we enforce the inputs are exactly equal. we enforce the outputs are exactly equal when `is_final = true`.
        let ctx = pool.main();
        for ((table_i, table_o), (call_i, call_o)) in
            virtual_table.zip_eq(fix_len_vt.chain(var_len_vt))
        {
            constrain_vec_equal(ctx, &table_i.packed_input, &call_i.packed_input);
            ctx.constrain_equal(&table_i.is_final, &call_i.is_final);
            let is_final = SafeTypeChip::unsafe_to_bool(table_i.is_final);
            enforce_conditional_equality(ctx, gate, table_o.hash.hi(), call_o.hash.hi(), is_final);
            enforce_conditional_equality(ctx, gate, table_o.hash.lo(), call_o.hash.lo(), is_final);
        }
    }

    /// Consumes all collected calls and raw assigns them to the keccak sub-circuit specified by `keccak_config`. Then constrains that the [`LoadedKeccakF`]s must equal the virtually assigned calls.
    ///
    /// This is the only function you need to call to process all calls.
    ///
    /// ## Assumptions
    /// - This should be the **only** time `layouter` is allowed to assign to `keccak_config`.
    /// - `range_chip` should share same reference to `copy_manager` as `pool`.
    pub fn assign_raw_and_constrain(
        self,
        keccak_circuit_params: KeccakConfigParams,
        keccak_config: &KeccakCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
        pool: &mut SinglePhaseCoreManager<F>,
        range_chip: &RangeChip<F>,
    ) -> Result<(), plonk::Error> {
        // We constrain the collected keccak calls using the vanilla zkEVM keccak circuit:
        // convert `calls` to actual keccak inputs as bytes (Vec<u8>)
        let keccak_inputs = self.format_keccak_inputs();
        // raw synthesize of vanilla keccak circuit:
        let keccak_assigned_rows: Vec<KeccakAssignedRow<F>> = layouter.assign_region(
            || "vanilla keccak circuit",
            |mut region| {
                let (keccak_rows, _) =
                    multi_keccak::<F>(&keccak_inputs, None, keccak_circuit_params);
                Ok(keccak_config.assign(&mut region, &keccak_rows))
            },
        )?;
        // Convert raw assigned cells into virtual cells
        let virtual_keccak_fs = transmute_keccak_assigned_to_virtual(
            &pool.copy_manager,
            keccak_assigned_rows,
            keccak_circuit_params.rows_per_round,
        );
        self.pack_and_constrain(virtual_keccak_fs, pool, range_chip);
        Ok(())
    }
}

#[cfg(feature = "aggregation")]
mod aggregation {
    use crate::Field;
    use snark_verifier_sdk::CircuitExt;

    use crate::utils::build_utils::aggregation::CircuitMetadata;

    use super::{EthCircuitInstructions, RlcKeccakCircuitImpl};

    impl<F, I> CircuitExt<F> for RlcKeccakCircuitImpl<F, I>
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

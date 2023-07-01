use std::{
    collections::{HashMap, HashSet},
    env::var,
    iter, mem,
};

use halo2_base::{
    gates::{
        builder::{
            assign_threads_in, FlexGateConfigParams, GateThreadBuilder,
            KeygenAssignments as GateKeygenAssignments, MultiPhaseThreadBreakPoints,
            ThreadBreakPoints,
        },
        flex_gate::FlexGateConfig,
    },
    halo2_proofs::{
        circuit::{self, Region, Value},
        plonk::{Advice, Column, Selector},
    },
    utils::ScalarField,
    Context,
};
use serde::{Deserialize, Serialize};

use super::rlc::{RlcChip, RlcConfig, RlcContextPair, FIRST_PHASE, RLC_PHASE};
use crate::util::EthConfigParams;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RlcThreadBreakPoints {
    pub gate: MultiPhaseThreadBreakPoints,
    pub rlc: ThreadBreakPoints,
}

#[derive(Clone, Debug, Default)]
pub struct KeygenAssignments<F: ScalarField> {
    pub assigned_advices: HashMap<(usize, usize), (circuit::Cell, usize)>,
    pub assigned_constants: HashMap<F, circuit::Cell>,
    pub break_points: RlcThreadBreakPoints,
}

#[derive(Clone, Debug, Default)]
pub struct RlcThreadBuilder<F: ScalarField> {
    /// Threads for RLC assignment, assume only in `RLC_PHASE` for now
    pub threads_rlc: Vec<Context<F>>,
    /// [`GateThreadBuilder`] with threads for basic gate; also in charge of thread IDs
    pub gate_builder: GateThreadBuilder<F>,
}

impl<F: ScalarField> RlcThreadBuilder<F> {
    // re-expose some methods from [`GateThreadBuilder`] for convenience
    #[allow(unused_mut)]
    pub fn new(mut witness_gen_only: bool) -> Self {
        // in non halo2-axiom, the prover calls `synthesize` twice: first just to get FirstPhase advice columns, commit, and then generate challenge value; then the second time to actually compute SecondPhase advice
        // our "Prover" implementation (`witness_gen_only = true`) is heavily optimized for the Axiom version, which only calls `synthesize` once
        #[cfg(not(feature = "halo2-axiom"))]
        {
            witness_gen_only = false;
        }
        Self { threads_rlc: Vec::new(), gate_builder: GateThreadBuilder::new(witness_gen_only) }
    }

    pub fn mock() -> Self {
        Self::new(false)
    }

    pub fn keygen() -> Self {
        Self::new(false).unknown(true)
    }

    pub fn prover() -> Self {
        Self::new(true)
    }

    pub fn unknown(mut self, use_unknown: bool) -> Self {
        self.gate_builder = self.gate_builder.unknown(use_unknown);
        self
    }

    pub fn rlc_ctx_pair(&mut self) -> RlcContextPair<F> {
        if self.threads_rlc.is_empty() {
            self.new_thread_rlc();
        }
        (self.gate_builder.main(RLC_PHASE), self.threads_rlc.last_mut().unwrap())
    }

    pub fn witness_gen_only(&self) -> bool {
        self.gate_builder.witness_gen_only()
    }

    pub fn use_unknown(&self) -> bool {
        self.gate_builder.use_unknown()
    }

    pub fn thread_count(&self) -> usize {
        self.gate_builder.thread_count()
    }

    pub fn get_new_thread_id(&mut self) -> usize {
        self.gate_builder.get_new_thread_id()
    }

    pub fn new_thread_rlc(&mut self) -> &mut Context<F> {
        let thread_id = self.get_new_thread_id();
        self.threads_rlc.push(Context::new(self.witness_gen_only(), thread_id));
        self.threads_rlc.last_mut().unwrap()
    }

    /// Auto-calculate configuration parameters for the circuit
    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> EthConfigParams {
        // first auto-configure the basic gates and lookup advice columns
        let FlexGateConfigParams {
            strategy: _,
            num_advice_per_phase,
            num_lookup_advice_per_phase,
            num_fixed: _,
            k,
        } = self.gate_builder.config(k, minimum_rows);
        // now calculate how many RLC advice columns are needed
        let max_rows = (1 << k) - minimum_rows.unwrap_or(0);
        let total_rlc_advice = self.threads_rlc.iter().map(|ctx| ctx.advice.len()).sum::<usize>();
        // we do a rough estimate by taking ceil(advice_cells_per_phase / 2^k )
        // if there is an edge case, `minimum_rows` will need to be manually adjusted
        let num_rlc_columns = (total_rlc_advice + max_rows - 1) / max_rows;
        // total fixed is the total number of constants used in both gate_builder and RLC so we need to re-calculate:
        let total_fixed: usize = HashSet::<F>::from_iter(
            self.gate_builder
                .threads
                .iter()
                .flatten()
                .chain(self.threads_rlc.iter())
                .flat_map(|ctx| ctx.constant_equality_constraints.iter().map(|(c, _)| *c)),
        )
        .len();
        let num_fixed = (total_fixed + (1 << k) - 1) >> k;
        // assemble into new config params
        let params = EthConfigParams {
            degree: k as u32,
            num_rlc_columns,
            num_range_advice: num_advice_per_phase,
            num_lookup_advice: num_lookup_advice_per_phase,
            num_fixed,
            unusable_rows: minimum_rows.unwrap_or(0),
            keccak_rows_per_round: 0,
            lookup_bits: var("LOOKUP_BITS").map(|s| s.parse().ok()).unwrap_or(None),
        };
        #[cfg(feature = "display")]
        {
            println!("RLC Chip | {total_rlc_advice} advice cells");
            log::info!("RlcThreadBuilder auto-calculated config params:\n {params:#?}");
        }
        std::env::set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
        params
    }

    /// Assigns all advice and fixed cells, turns on selectors, imposes equality constraints.
    /// This should only be called during keygen.
    pub fn assign_all(
        &mut self,
        gate: &FlexGateConfig<F>,
        lookup_advice: &[Vec<Column<Advice>>],
        q_lookup: &[Option<Selector>],
        rlc: &RlcConfig<F>,
        region: &mut Region<F>,
        KeygenAssignments {
            mut assigned_advices,
            assigned_constants,
            mut break_points,
        }: KeygenAssignments<F>,
    ) -> KeygenAssignments<F> {
        // assert!(!self.witness_gen_only());
        if rlc.basic_gates.is_empty() {
            return KeygenAssignments { assigned_advices, assigned_constants, break_points };
        }
        let use_unknown = self.use_unknown();
        let max_rows = gate.max_rows;

        // first we assign all RLC contexts, basically copying gate::builder::assign_all except that the length of the RLC vertical gate is 3 instead of 4 (which was length of basic gate)
        let mut gate_index = 0;
        let mut row_offset = 0;
        let mut basic_gate = rlc.basic_gates[0];
        for ctx in self.threads_rlc.iter() {
            // TODO: if we have more similar vertical gates this should be refactored into a general function
            for (i, (&advice, &q)) in
                ctx.advice.iter().zip(ctx.selector.iter().chain(iter::repeat(&false))).enumerate()
            {
                let (mut column, mut q_rlc) = basic_gate;
                let value = if use_unknown { Value::unknown() } else { Value::known(advice) };
                #[cfg(feature = "halo2-axiom")]
                let cell = *region.assign_advice(column, row_offset, value).cell();
                #[cfg(not(feature = "halo2-axiom"))]
                let cell =
                    region.assign_advice(|| "", column, row_offset, || value).unwrap().cell();
                assigned_advices.insert((ctx.context_id, i), (cell, row_offset));

                if (q && row_offset + 3 > max_rows) || row_offset >= max_rows - 1 {
                    break_points.rlc.push(row_offset);
                    row_offset = 0;
                    gate_index += 1;
                    // when there is a break point, because we may have two gates that overlap at the current cell, we must copy the current cell to the next column for safety
                    basic_gate = *rlc
                        .basic_gates
                        .get(gate_index)
                        .unwrap_or_else(|| panic!("NOT ENOUGH RLC ADVICE COLUMNS. Perhaps blinding factors were not taken into account. The max non-poisoned rows is {max_rows}"));
                    (column, q_rlc) = basic_gate;

                    #[cfg(feature = "halo2-axiom")]
                    {
                        let ncell = region.assign_advice(column, row_offset, value);
                        region.constrain_equal(ncell.cell(), &cell);
                    }
                    #[cfg(not(feature = "halo2-axiom"))]
                    {
                        let ncell = region
                            .assign_advice(|| "", column, row_offset, || value)
                            .unwrap()
                            .cell();
                        region.constrain_equal(ncell, cell).unwrap();
                    }
                }

                if q {
                    q_rlc.enable(region, row_offset).expect("enable selector should not fail");
                }
                row_offset += 1;
            }
        }
        // in order to constrain equalities and assign constants, we copy the RLC equality constraints into the gate builder (it doesn't matter which context the equalities are in), so `GateThreadBuilder::assign_all` can take care of it
        // the phase doesn't matter for equality constraints, so we use phase 0 since we're sure there's a main context there
        let main_ctx = self.gate_builder.main(0);
        for ctx in self.threads_rlc.iter_mut() {
            main_ctx.advice_equality_constraints.append(&mut ctx.advice_equality_constraints);
            main_ctx.constant_equality_constraints.append(&mut ctx.constant_equality_constraints);
        }
        let assignments = self.gate_builder.assign_all(
            gate,
            lookup_advice,
            q_lookup,
            region,
            GateKeygenAssignments {
                assigned_advices,
                assigned_constants,
                break_points: break_points.gate,
            },
        );

        KeygenAssignments {
            assigned_advices: assignments.assigned_advices,
            assigned_constants: assignments.assigned_constants,
            break_points: RlcThreadBreakPoints {
                gate: assignments.break_points,
                rlc: break_points.rlc,
            },
        }
    }
}

/// Pure advice witness assignment in a single phase. Uses preprocessed `break_points` to determine when
/// to split a thread into a new column.
pub fn assign_threads_rlc<F: ScalarField>(
    threads_rlc: Vec<Context<F>>,
    rlc: &RlcConfig<F>,
    region: &mut Region<F>,
    break_points: ThreadBreakPoints,
) {
    if rlc.basic_gates.is_empty() {
        assert!(threads_rlc.is_empty(), "Trying to assign threads in a phase with no columns");
        return;
    }
    let mut break_points = break_points.into_iter();
    let mut break_point = break_points.next();

    let mut gate_index = 0;
    let (mut column, _) = rlc.basic_gates[gate_index];
    let mut row_offset = 0;

    for ctx in threads_rlc {
        for advice in ctx.advice {
            #[cfg(feature = "halo2-axiom")]
            region.assign_advice(column, row_offset, Value::known(advice));
            #[cfg(not(feature = "halo2-axiom"))]
            region.assign_advice(|| "", column, row_offset, || Value::known(advice)).unwrap();

            if break_point == Some(row_offset) {
                break_point = break_points.next();
                row_offset = 0;
                gate_index += 1;
                (column, _) = rlc.basic_gates[gate_index];

                #[cfg(feature = "halo2-axiom")]
                region.assign_advice(column, row_offset, Value::known(advice));
                #[cfg(not(feature = "halo2-axiom"))]
                region.assign_advice(|| "", column, row_offset, || Value::known(advice)).unwrap();
            }

            row_offset += 1;
        }
    }
}

pub trait FnSynthesize<F> = FnOnce(&mut RlcThreadBuilder<F>, &RlcChip<F>) + Clone; // `Clone` because we may run synthesize multiple times on the same circuit during keygen or mock stages

// re-usable function for phase 0 synthesize in prover mode
pub fn assign_prover_phase0<F: ScalarField>(
    region: &mut Region<F>,
    gate: &FlexGateConfig<F>,
    lookup_advice: &[Vec<Column<Advice>>],
    builder: &mut RlcThreadBuilder<F>,
    break_points: &mut RlcThreadBreakPoints,
) {
    let break_points_gate = mem::take(&mut break_points.gate[FIRST_PHASE]);
    // warning: we currently take all contexts from phase 0, which means you can't read the values
    // from these contexts later in phase 1. If we want to read, should clone here
    let threads = mem::take(&mut builder.gate_builder.threads[FIRST_PHASE]);
    // assign phase 0
    assign_threads_in(
        FIRST_PHASE,
        threads,
        gate,
        &lookup_advice[FIRST_PHASE],
        region,
        break_points_gate,
    );
    log::info!("End of FirstPhase");
}

// re-usable function for phase 1 synthesize in prover mode
#[allow(clippy::too_many_arguments)]
pub fn assign_prover_phase1<F: ScalarField>(
    region: &mut Region<F>,
    gate: &FlexGateConfig<F>,
    lookup_advice: &[Vec<Column<Advice>>],
    rlc_config: &RlcConfig<F>,
    rlc_chip: &RlcChip<F>,
    builder: &mut RlcThreadBuilder<F>,
    break_points: &mut RlcThreadBreakPoints,
    f: impl FnSynthesize<F>,
) {
    let break_points_gate = mem::take(&mut break_points.gate[RLC_PHASE]);
    let break_points_rlc = mem::take(&mut break_points.rlc);

    // generate witnesses depending on challenge
    f(builder, rlc_chip);

    let threads = mem::take(&mut builder.gate_builder.threads[RLC_PHASE]);
    // assign phase 1
    assign_threads_in(
        RLC_PHASE,
        threads,
        gate,
        &lookup_advice[RLC_PHASE],
        region,
        break_points_gate,
    );

    let threads_rlc = mem::take(&mut builder.threads_rlc);
    assign_threads_rlc(threads_rlc, rlc_config, region, break_points_rlc);
}

pub use circuit_builder::*;
mod circuit_builder {
    use std::cell::RefCell;

    use crate::util::EthConfigParams;

    use crate::rlp::{
        builder::*,
        rlc::{RlcChip, RlcConfig},
        RlcGateConfig, RlpConfig,
    };
    use halo2_base::{
        gates::flex_gate::{FlexGateConfig, GateStrategy},
        halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner},
            plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
        },
        utils::ScalarField,
        SKIP_FIRST_PASS,
    };
    // The circuits below are mostly used for testing.
    // Unfortunately for `KeccakCircuitBuilder` we still need to do some more custom stuff beyond what's in this circuit
    // due to the intricacies of 2-phase challenge API.

    /// A wrapper struct to auto-build a circuit from a `RlcThreadBuilder`.
    ///
    /// This struct is trickier because it uses the Multi-phase Challenge API. The intended use is as follows:
    /// * The user can run phase 0 calculations on `builder` outside of the circuit (as usual) and supply the builder to construct the circuit.
    /// * The user also specifies a closure `synthesize_phase1(builder, challenge)` that specifies all calculations that should be done in phase 1.
    /// The builder will then handle the process of assigning all advice cells in phase 1, squeezing a challenge value `challenge` from the backend API, and then using that value to do all phase 1 witness generation.
    pub struct RlcCircuitBuilder<F: ScalarField, FnPhase1>
    where
        FnPhase1: FnSynthesize<F>,
    {
        pub builder: RefCell<RlcThreadBuilder<F>>,
        pub break_points: RefCell<RlcThreadBreakPoints>, // `RefCell` allows the circuit to record break points in a keygen call of `synthesize` for use in later witness gen
        // we guarantee that `synthesize_phase1` is called *exactly once* during the proving stage, but since `Circuit::synthesize` takes `&self`, and `assign_region` takes a `Fn` instead of `FnOnce`, we need some extra engineering:
        pub synthesize_phase1: RefCell<Option<FnPhase1>>,
    }

    impl<F: ScalarField, FnPhase1> RlcCircuitBuilder<F, FnPhase1>
    where
        FnPhase1: FnSynthesize<F>,
    {
        pub fn new(
            builder: RlcThreadBuilder<F>,
            break_points: Option<RlcThreadBreakPoints>,
            synthesize_phase1: FnPhase1,
        ) -> Self {
            Self {
                builder: RefCell::new(builder),
                break_points: RefCell::new(break_points.unwrap_or_default()),
                synthesize_phase1: RefCell::new(Some(synthesize_phase1)),
            }
        }

        pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> EthConfigParams {
            // clone everything so we don't alter the circuit in any way for later calls
            let mut builder = self.builder.borrow().clone();
            let f =
                self.synthesize_phase1.borrow().clone().expect("synthesize_phase1 should exist");
            f(&mut builder, &RlcChip::new(F::zero()));
            builder.config(k, minimum_rows)
        }

        // re-usable function for synthesize
        pub fn two_phase_synthesize(
            &self,
            gate: &FlexGateConfig<F>,
            lookup_advice: &[Vec<Column<Advice>>],
            q_lookup: &[Option<Selector>],
            rlc: &RlcConfig<F>,
            layouter: &mut impl Layouter<F>,
        ) {
            let mut first_pass = SKIP_FIRST_PASS;
            #[cfg(feature = "halo2-axiom")]
            let witness_gen_only = self.builder.borrow().witness_gen_only();
            // in non halo2-axiom, the prover calls `synthesize` twice: first just to get FirstPhase advice columns, commit, and then generate challenge value; then the second time to actually compute SecondPhase advice
            // our "Prover" implementation is heavily optimized for the Axiom version, which only calls `synthesize` once
            #[cfg(not(feature = "halo2-axiom"))]
            let witness_gen_only = false;

            let mut gamma = None;
            if !witness_gen_only {
                // in these cases, synthesize is called twice, and challenge can be gotten after the first time, or we use dummy value 0
                layouter.get_challenge(rlc.gamma).map(|gamma_| gamma = Some(gamma_));
            }

            layouter
                .assign_region(
                    || "RlcCircuitBuilder generated circuit",
                    |mut region| {
                        if first_pass {
                            first_pass = false;
                            return Ok(());
                        }
                        if !witness_gen_only {
                            let mut builder = self.builder.borrow().clone();
                            let f = self
                                .synthesize_phase1
                                .borrow()
                                .clone()
                                .expect("synthesize_phase1 should exist");
                            // call the actual synthesize function
                            let rlc_chip = RlcChip::new(gamma.unwrap_or_else(|| F::zero()));
                            f(&mut builder, &rlc_chip);
                            let KeygenAssignments {
                                assigned_advices: _,
                                assigned_constants: _,
                                break_points,
                            } = builder.assign_all(
                                gate,
                                lookup_advice,
                                q_lookup,
                                rlc,
                                &mut region,
                                Default::default(),
                            );
                            *self.break_points.borrow_mut() = break_points;
                        } else {
                            let builder = &mut self.builder.borrow_mut();
                            let break_points = &mut self.break_points.borrow_mut();
                            assign_prover_phase0(
                                &mut region,
                                gate,
                                lookup_advice,
                                builder,
                                break_points,
                            );
                            // this is a special backend API function (in halo2-axiom only) that computes the KZG commitments for all columns in FirstPhase and performs Fiat-Shamir on them to return the challenge value
                            #[cfg(feature = "halo2-axiom")]
                            region.next_phase();
                            // get challenge value
                            let mut gamma = None;
                            #[cfg(feature = "halo2-axiom")]
                            region.get_challenge(rlc.gamma).map(|gamma_| {
                                log::info!("gamma: {gamma_:?}");
                                gamma = Some(gamma_);
                            });
                            let rlc_chip = RlcChip::new(
                                gamma.expect("Could not get challenge in second phase"),
                            );
                            let f = RefCell::take(&self.synthesize_phase1)
                                .expect("synthesize_phase1 should exist"); // we `take` the closure during proving to avoid cloning captured variables (the captured variables would be the AssignedValue payload sent from FirstPhase to SecondPhase)
                            assign_prover_phase1(
                                &mut region,
                                gate,
                                lookup_advice,
                                rlc,
                                &rlc_chip,
                                builder,
                                break_points,
                                f,
                            );
                        }
                        Ok(())
                    },
                )
                .unwrap();
        }
    }

    impl<F: ScalarField, FnPhase1> Circuit<F> for RlcCircuitBuilder<F, FnPhase1>
    where
        FnPhase1: FnSynthesize<F>,
    {
        type Config = RlcGateConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> RlcGateConfig<F> {
            let EthConfigParams {
                degree,
                num_rlc_columns,
                num_range_advice,
                num_lookup_advice: _,
                num_fixed,
                unusable_rows: _,
                keccak_rows_per_round: _,
                lookup_bits: _,
            } = serde_json::from_str(&std::env::var("ETH_CONFIG_PARAMS").unwrap()).unwrap();
            let mut gate = FlexGateConfig::configure(
                meta,
                GateStrategy::Vertical,
                &num_range_advice,
                num_fixed,
                degree as usize,
            );
            let rlc = RlcConfig::configure(meta, num_rlc_columns);
            // number of blinding factors may have changed due to introduction of new RLC gate
            gate.max_rows = (1 << degree) - meta.minimum_rows();
            RlcGateConfig { gate, rlc }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            self.two_phase_synthesize(&config.gate, &[], &[], &config.rlc, &mut layouter);
            Ok(())
        }
    }

    /// A wrapper around RlcCircuitBuilder where Gate is replaced by Range in the circuit
    pub struct RlpCircuitBuilder<F: ScalarField, FnPhase1>(RlcCircuitBuilder<F, FnPhase1>)
    where
        FnPhase1: FnSynthesize<F>;

    impl<F: ScalarField, FnPhase1> RlpCircuitBuilder<F, FnPhase1>
    where
        FnPhase1: FnSynthesize<F>,
    {
        pub fn new(
            builder: RlcThreadBuilder<F>,
            break_points: Option<RlcThreadBreakPoints>,
            synthesize_phase1: FnPhase1,
        ) -> Self {
            Self(RlcCircuitBuilder::new(builder, break_points, synthesize_phase1))
        }

        pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> EthConfigParams {
            self.0.config(k, minimum_rows)
        }
    }

    impl<F: ScalarField, FnPhase1> Circuit<F> for RlpCircuitBuilder<F, FnPhase1>
    where
        FnPhase1: FnSynthesize<F>,
    {
        type Config = RlpConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> RlpConfig<F> {
            let EthConfigParams {
                degree,
                num_rlc_columns,
                num_range_advice,
                num_lookup_advice,
                num_fixed,
                unusable_rows: _,
                keccak_rows_per_round: _,
                lookup_bits: _,
            } = serde_json::from_str(&std::env::var("ETH_CONFIG_PARAMS").unwrap()).unwrap();
            let lookup_bits = std::env::var("LOOKUP_BITS").unwrap().parse().unwrap();
            RlpConfig::configure(
                meta,
                num_rlc_columns,
                &num_range_advice,
                &num_lookup_advice,
                num_fixed,
                lookup_bits,
                degree as usize,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.range.load_lookup_table(&mut layouter)?;
            self.0.two_phase_synthesize(
                &config.range.gate,
                &config.range.lookup_advice,
                &config.range.q_lookup,
                &config.rlc,
                &mut layouter,
            );
            Ok(())
        }
    }
}

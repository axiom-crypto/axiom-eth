use std::cell::{OnceCell, RefCell};

use halo2_base::{
    gates::{RangeChip, RangeInstructions},
    halo2_proofs::{circuit::Layouter, plonk::ConstraintSystem},
    utils::ScalarField,
};

use crate::rlc::circuit::{
    builder::RlcCircuitBuilder, instructions::RlcCircuitInstructions, RlcCircuitParams, RlcConfig,
};

use super::two_phase::{TwoPhaseCircuit, TwoPhaseCircuitInstructions};

/// This struct provides a quick way to create a circuit that only uses [RlcConfig] that
/// is less verbose than implementing [TwoPhaseCircuitInstructions] directly.
///
/// If additional in-circuit logic is required or columns not managed by [RlcConfig] are necessary,
/// then one needs to create a new struct (often a circuit builder) that implements
/// [TwoPhaseCircuitInstructions] directly.
pub struct RlcExecutor<F: ScalarField, I: RlcCircuitInstructions<F>> {
    pub logic_inputs: I,
    pub range_chip: RangeChip<F>,
    pub builder: RefCell<RlcCircuitBuilder<F>>,
    /// The FirstPhasePayload is set after FirstPhase witness generation.
    /// This is used both to pass payload between phases and also to detect if `generate_witnesses_phase0`
    /// was already run outside of `synthesize` (e.g., to determine public instances)
    pub payload: RefCell<OnceCell<I::FirstPhasePayload>>,
}

pub type RlcCircuit<F, I> = TwoPhaseCircuit<F, RlcExecutor<F, I>>;

impl<F: ScalarField, I> RlcExecutor<F, I>
where
    I: RlcCircuitInstructions<F>,
{
    pub fn new(builder: RlcCircuitBuilder<F>, logic_inputs: I) -> RlcCircuit<F, I> {
        let range_chip = builder.base.range_chip();
        let ex = Self {
            logic_inputs,
            range_chip,
            builder: RefCell::new(builder),
            payload: RefCell::new(OnceCell::new()),
        };
        TwoPhaseCircuit::new(ex)
    }

    pub fn calculate_params(&self, minimum_rows: Option<usize>) -> RlcCircuitParams {
        let mut builder = self.builder.borrow().deep_clone();
        let range_chip = builder.base.range_chip();
        let payload = I::virtual_assign_phase0(&self.logic_inputs, &mut builder, &range_chip);
        // as long as not in Prover stage, this will just set challenge = 0
        let rlc_chip = builder.rlc_chip(range_chip.gate());
        I::virtual_assign_phase1(&mut builder, &range_chip, &rlc_chip, payload);
        let params = builder.calculate_params(minimum_rows);
        builder.clear(); // clear so dropping copy manager doesn't complain
        self.builder.borrow_mut().set_params(params.clone());
        params
    }
}

impl<F, I> TwoPhaseCircuitInstructions<F> for RlcExecutor<F, I>
where
    F: ScalarField,
    I: RlcCircuitInstructions<F>,
{
    type Config = RlcConfig<F>;
    type Params = RlcCircuitParams;

    fn params(&self) -> Self::Params {
        self.builder.borrow().params()
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        RlcConfig::configure(meta, params)
    }

    /// We never clear if running a real proof for "halo2-axiom".
    fn clear(&self) {
        if self.builder.borrow().witness_gen_only() {
            return;
        }
        self.builder.borrow_mut().clear();
        self.payload.borrow_mut().take();
    }

    fn initialize(&self, config: &Self::Config, mut layouter: impl Layouter<F>) {
        config.base.initialize(&mut layouter);
    }

    fn virtual_assign_phase0(&self) {
        if self.payload.borrow().get().is_some() {
            return;
        }
        let mut builder = self.builder.borrow_mut();
        let payload = I::virtual_assign_phase0(&self.logic_inputs, &mut builder, &self.range_chip);
        let _ = self.payload.borrow().set(payload);
    }

    fn raw_synthesize_phase0(&self, config: &Self::Config, layouter: impl Layouter<F>) {
        self.builder.borrow().raw_synthesize_phase0(config, layouter);
    }

    fn load_challenges(&self, config: &Self::Config, layouter: impl Layouter<F>) {
        self.builder.borrow_mut().load_challenge(config, layouter);
    }

    fn virtual_assign_phase1(&self) {
        let payload =
            self.payload.borrow_mut().take().expect("FirstPhase witness generation was not run");
        let mut builder = self.builder.borrow_mut();
        let rlc_chip = builder.rlc_chip(self.range_chip.gate());
        I::virtual_assign_phase1(&mut builder, &self.range_chip, &rlc_chip, payload)
    }

    fn raw_synthesize_phase1(&self, config: &Self::Config, layouter: impl Layouter<F>) {
        self.builder.borrow().raw_synthesize_phase1(config, layouter, true);
    }
}

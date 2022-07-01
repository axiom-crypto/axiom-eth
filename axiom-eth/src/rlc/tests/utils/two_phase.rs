//! Template for functions a circuit should implement to work with two challenge phases,
//! with particular attention to

use std::marker::PhantomData;

use halo2_base::{
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    utils::ScalarField,
};

/// Interface for what functions need to be supplied to write a circuit that
/// uses two challenge phases.
pub trait TwoPhaseCircuitInstructions<F: ScalarField> {
    type Config: Clone;
    type Params: Clone + Default;

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config;
    fn params(&self) -> Self::Params;
    /// The multi-phase challenge API requires `Circuit::synthesize` to be called multiple times unless in `create_proof` mode and using `halo2-axiom`. To prevent issues with
    /// the multiple calls, we require a function to clear the state of any circuit builders.
    fn clear(&self);
    // Instructions are listed in order they will be run
    fn initialize(&self, _config: &Self::Config, _layouter: impl Layouter<F>) {}
    /// Phase0 assign to virtual regions. Any data passing from phase0 to phase1 will be done internally within the circuit and stored in `OnceCell` or `RefCell`.
    fn virtual_assign_phase0(&self);
    fn raw_synthesize_phase0(&self, config: &Self::Config, layouter: impl Layouter<F>);
    fn load_challenges(&self, config: &Self::Config, layouter: impl Layouter<F>);
    fn virtual_assign_phase1(&self);
    fn raw_synthesize_phase1(&self, config: &Self::Config, layouter: impl Layouter<F>);
}

// Rust does not like blanket implementations of `Circuit` for multiple other traits.
// To get around this, we will wrap `TwoPhaseCircuitInstructions`
#[derive(Clone, Debug)]
pub struct TwoPhaseCircuit<F: ScalarField, CI: TwoPhaseCircuitInstructions<F>>(
    pub CI,
    PhantomData<F>,
);

impl<F: ScalarField, CI: TwoPhaseCircuitInstructions<F>> TwoPhaseCircuit<F, CI> {
    pub fn new(instructions: CI) -> Self {
        Self(instructions, PhantomData)
    }
}

impl<F: ScalarField, CI: TwoPhaseCircuitInstructions<F>> Circuit<F> for TwoPhaseCircuit<F, CI> {
    type Config = CI::Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = CI::Params;

    fn params(&self) -> Self::Params {
        self.0.params()
    }

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        CI::configure_with_params(meta, params)
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!()
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // clear in case synthesize is called multiple times
        self.0.clear();
        self.0.initialize(&config, layouter.namespace(|| "initialize"));
        self.0.virtual_assign_phase0();
        self.0.raw_synthesize_phase0(&config, layouter.namespace(|| "raw synthesize phase0"));
        #[cfg(feature = "halo2-axiom")]
        {
            layouter.next_phase();
        }
        self.0.load_challenges(&config, layouter.namespace(|| "load challenges"));
        self.0.virtual_assign_phase1();
        self.0.raw_synthesize_phase1(&config, layouter.namespace(|| "raw synthesize phase1"));
        Ok(())
    }
}

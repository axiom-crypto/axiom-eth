use halo2_base::{
    gates::{circuit::MaybeRangeConfig, RangeChip},
    halo2_proofs::circuit::Layouter,
    utils::ScalarField,
    virtual_region::manager::VirtualRegionManager,
};

use crate::rlc::{
    chip::RlcChip,
    circuit::{builder::RlcCircuitBuilder, RlcConfig},
};

impl<F: ScalarField> RlcCircuitBuilder<F> {
    /// Assigns the raw Halo2 cells for [RlcConfig] in FirstPhase. This should be the only time
    /// FirstPhase cells are assigned to [RlcConfig].
    ///
    /// This also imposes the equality constraints on
    /// public instance columns (requires the copy manager to be assigned).
    ///
    /// (We are only imposing the copy constraints on the instance column, not assigning values to the instance column --
    /// The instance values are provided in `create_proof` as an argument, and that is what is used for Fiat-Shamir.
    /// Therefore the equality constraints on instance columsn can also be done in SecondPhase instead.
    /// We keep it in FirstPhase for logical clarity.)
    pub fn raw_synthesize_phase0(&self, config: &RlcConfig<F>, mut layouter: impl Layouter<F>) {
        let usable_rows = config.rlc.usable_rows;
        layouter
            .assign_region(
                || "base phase 0",
                |mut region| {
                    self.base.core().phase_manager[0]
                        .assign_raw(&(config.basic_gates(0), usable_rows), &mut region);
                    if let MaybeRangeConfig::WithRange(config) = &config.base.base {
                        self.base.assign_lookups_in_phase(config, &mut region, 0);
                    }
                    Ok(())
                },
            )
            .unwrap();
        self.base.assign_instances(&config.base.instance, layouter.namespace(|| "expose public"));
    }

    /// Loads challenge value `gamma`, if after FirstPhase
    pub fn load_challenge(&mut self, config: &RlcConfig<F>, layouter: impl Layouter<F>) {
        let gamma = layouter.get_challenge(config.rlc.gamma);
        gamma.map(|g| self.gamma = Some(g));
        log::info!("Challenge value: {gamma:?}");
    }

    /// Assigns the raw Halo2 cells for [RlcConfig] (which is [BaseConfig] and [PureRlcConfig])
    /// in SecondPhase. This should be the only time SecondPhase cells are assigned to [RlcConfig],
    /// i.e., there is not shared ownership of some columns.
    ///
    /// If there is nothing after this that uses [CopyConstraintManager], then `enforce_copy_constraints` should
    /// be set to true (this is usually the default).
    pub fn raw_synthesize_phase1(
        &self,
        config: &RlcConfig<F>,
        mut layouter: impl Layouter<F>,
        enforce_copy_constraints: bool,
    ) {
        let usable_rows = config.rlc.usable_rows;
        layouter
            .assign_region(
                || "base+rlc phase 1",
                |mut region| {
                    let core = self.base.core();
                    core.phase_manager[1]
                        .assign_raw(&(config.basic_gates(1), usable_rows), &mut region);
                    if let MaybeRangeConfig::WithRange(config) = &config.base.base {
                        self.base.assign_lookups_in_phase(config, &mut region, 1);
                    }
                    self.rlc_manager.assign_raw(&config.rlc, &mut region);
                    // Impose equality constraints
                    if enforce_copy_constraints && !core.witness_gen_only() {
                        core.copy_manager.assign_raw(config.base.constants(), &mut region);
                    }
                    Ok(())
                },
            )
            .unwrap();
    }
}

/// Simple trait describing the FirstPhase and SecondPhase witness generation of a circuit
/// that only uses [RlcConfig]. This is mostly provided for convenience to use with
/// [RlcExecutor]; for more customization
/// you will have to implement [TwoPhaseInstructions] directly.
pub trait RlcCircuitInstructions<F: ScalarField> {
    type FirstPhasePayload;

    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
    ) -> Self::FirstPhasePayload;

    fn virtual_assign_phase1(
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
        rlc: &RlcChip<F>,
        payload: Self::FirstPhasePayload,
    );
}

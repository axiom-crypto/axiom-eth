use std::marker::PhantomData;

use halo2_base::{
    gates::{
        circuit::{BaseCircuitParams, BaseConfig},
        flex_gate::BasicGateConfig,
    },
    halo2_proofs::{
        plonk::{Challenge, ConstraintSystem, Expression, FirstPhase, SecondPhase},
        poly::Rotation,
    },
    utils::ScalarField,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

/// The circuit builder that coordinates all virtual region managers to support [BaseConfig] and [RlcConfig]
pub mod builder;
/// Module to help auto-implement [TwoPhaseCircuitInstructions] using [RlcCircuitBuilder]
pub mod instructions;

/// This config consists of a variable number of advice columns, all in [SecondPhase].
/// Each advice column has a selector column that enables a custom gate to aid RLC computation.
///
/// The intention is that this chip is only used for the actual RLC computation. All other operations should use `GateInstructions` by advancing the phase to [SecondPhase].
///
/// Note: this uses a similar vertical gate structure as [FlexGateConfig] **however** the RLC gate uses only 3 contiguous rows instead of 4.
///
/// We re-use the [BasicGateConfig] struct for the RLC gate, but do not call `BasicGateConfig::configure` because the custom gate we use here is different.
#[derive(Clone, Debug)]
pub struct PureRlcConfig<F: ScalarField> {
    pub basic_gates: Vec<BasicGateConfig<F>>,
    pub gamma: Challenge,
    /// Total number of usable (non-poisoned) rows in the circuit.
    pub usable_rows: usize,
    _marker: PhantomData<F>,
}

impl<F: ScalarField> PureRlcConfig<F> {
    pub fn configure_from_challenge(
        meta: &mut ConstraintSystem<F>,
        k: usize,
        num_advice_col: usize,
        gamma: Challenge,
    ) -> Self {
        let basic_gates = (0..num_advice_col)
            .map(|_| {
                let a = meta.advice_column_in(SecondPhase);
                meta.enable_equality(a);
                let q = meta.selector();
                BasicGateConfig::new(q, a)
            })
            .collect_vec();

        for gate in &basic_gates {
            meta.create_gate("RLC computation", |meta| {
                let q = meta.query_selector(gate.q_enable);
                let rlc_prev = meta.query_advice(gate.value, Rotation::cur());
                let val = meta.query_advice(gate.value, Rotation::next());
                let rlc_curr = meta.query_advice(gate.value, Rotation(2));
                // TODO: see if reducing number of distinct rotation sets speeds up SHPLONK:
                // Phantom query so rotation set is also size 4 to match `FlexGateConfig`
                // meta.query_advice(rlc, Rotation(3));

                let gamma = meta.query_challenge(gamma);

                vec![q * (rlc_prev * gamma + val - rlc_curr)]
            });
        }
        log::info!("Poisoned rows after RlcConfig::configure {}", meta.minimum_rows());
        // Warning: this needs to be updated if you create more advice columns after this `RlcConfig` is created
        let usable_rows = (1usize << k) - meta.minimum_rows();

        Self { basic_gates, gamma, usable_rows, _marker: PhantomData }
    }
}

/// Configuration parameters for [RlcConfig]
#[derive(Clone, Default, Hash, Debug, Serialize, Deserialize)]
pub struct RlcCircuitParams {
    pub base: BaseCircuitParams,
    pub num_rlc_columns: usize,
}

/// Combination of [BaseConfig] and [PureRlcConfig].
// We name this `RlcConfig` because we almost never use `PureRlcConfig` by itself.
#[derive(Clone, Debug)]
pub struct RlcConfig<F: ScalarField> {
    pub base: BaseConfig<F>,
    pub rlc: PureRlcConfig<F>,
}

impl<F: ScalarField> RlcConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, params: RlcCircuitParams) -> Self {
        let gamma = meta.challenge_usable_after(FirstPhase);
        Self::configure_from_challenge(meta, params, gamma)
    }

    pub fn configure_from_challenge(
        meta: &mut ConstraintSystem<F>,
        params: RlcCircuitParams,
        gamma: Challenge,
    ) -> Self {
        let k = params.base.k;
        let mut base = BaseConfig::configure(meta, params.base);
        let rlc = PureRlcConfig::configure_from_challenge(meta, k, params.num_rlc_columns, gamma);
        base.set_usable_rows(rlc.usable_rows);
        RlcConfig { base, rlc }
    }

    pub fn basic_gates(&self, phase: usize) -> Vec<BasicGateConfig<F>> {
        self.base.gate().basic_gates[phase].clone()
    }

    pub fn set_usable_rows(&mut self, usable_rows: usize) {
        self.base.set_usable_rows(usable_rows);
        self.rlc.usable_rows = usable_rows;
    }
}

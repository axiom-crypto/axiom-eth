#![feature(int_log)]
#![feature(trait_alias)]
#![feature(return_position_impl_trait_in_trait)]
#![allow(incomplete_features)]

pub mod block_header;
pub mod keccak;
pub mod mpt;
pub mod rlp;
pub mod storage;
pub mod util;

#[cfg(feature = "providers")]
pub mod providers;

use crate::rlp::{
    builder::{RlcThreadBreakPoints, RlcThreadBuilder},
    rlc::RlcConfig,
    RlpConfig,
};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, RangeChip},
    halo2_proofs::{
        self,
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
    },
    AssignedValue,
};
use keccak::{FnSynthesize, KeccakCircuitBuilder, SharedKeccakChip};
pub use mpt::EthChip;
use serde::{Deserialize, Serialize};
use std::env::{set_var, var};
use util::EthConfigParams;
pub use zkevm_keccak::util::eth_types::Field;
use zkevm_keccak::KeccakConfig;

pub(crate) const ETH_LOOKUP_BITS: usize = 8; // always want 8 to range check bytes

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Network {
    Mainnet,
    Goerli,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Goerli => write!(f, "goerli"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MPTConfig<F: Field> {
    pub rlp: RlpConfig<F>,
    pub keccak: KeccakConfig<F>,
}

impl<F: Field> MPTConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, params: EthConfigParams) -> Self {
        let degree = params.degree;
        let mut rlp = RlpConfig::configure(
            meta,
            params.num_rlc_columns,
            &params.num_range_advice,
            &params.num_lookup_advice,
            params.num_fixed,
            params.lookup_bits.unwrap_or(ETH_LOOKUP_BITS),
            degree as usize,
        );
        set_var("KECCAK_DEGREE", degree.to_string());
        set_var("KECCAK_ROWS", params.keccak_rows_per_round.to_string());
        let keccak = KeccakConfig::new(meta, rlp.rlc.gamma);
        set_var("UNUSABLE_ROWS", meta.minimum_rows().to_string());
        #[cfg(feature = "display")]
        println!("Unusable rows: {}", meta.minimum_rows());
        rlp.range.gate.max_rows = (1 << degree) - meta.minimum_rows();
        Self { rlp, keccak }
    }
}

#[derive(Clone, Debug)]
/// Config shared for block header and storage proof circuits
pub struct EthConfig<F: Field> {
    mpt: MPTConfig<F>,
    pub instance: Column<Instance>,
}

impl<F: Field> EthConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, params: impl Into<EthConfigParams>) -> Self {
        let mpt = MPTConfig::configure(meta, params.into());
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self { mpt, instance }
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        &self.mpt.rlp.range.gate
    }
    pub fn range(&self) -> &RangeConfig<F> {
        &self.mpt.rlp.range
    }
    pub fn rlc(&self) -> &RlcConfig<F> {
        &self.mpt.rlp.rlc
    }
    pub fn rlp(&self) -> &RlpConfig<F> {
        &self.mpt.rlp
    }
    pub fn keccak(&self) -> &KeccakConfig<F> {
        &self.mpt.keccak
    }
    pub fn mpt(&self) -> &MPTConfig<F> {
        &self.mpt
    }
}

/// This is an extension of [`KeccakCircuitBuilder`] that adds support for public instances (aka public inputs+outputs)
///
/// The intended design is that [`KeccakCircuitBuilder`] is constructed and populated. In the process, the builder produces some assigned instances, which are supplied as `assigned_instances` to this struct.
/// The [`Circuit`] implementation for this struct will then expose these instances and constrain them using the Halo2 API.
pub struct EthCircuitBuilder<F: Field, FnPhase1: FnSynthesize<F>> {
    pub circuit: KeccakCircuitBuilder<F, FnPhase1>,
    pub assigned_instances: Vec<AssignedValue<F>>,
}

impl<F: Field, FnPhase1: FnSynthesize<F>> EthCircuitBuilder<F, FnPhase1> {
    pub fn new(
        assigned_instances: Vec<AssignedValue<F>>,
        builder: RlcThreadBuilder<F>,
        keccak: SharedKeccakChip<F>,
        range: RangeChip<F>,
        break_points: Option<RlcThreadBreakPoints>,
        synthesize_phase1: FnPhase1,
    ) -> Self {
        Self {
            assigned_instances,
            circuit: KeccakCircuitBuilder::new(
                builder,
                keccak,
                range,
                break_points,
                synthesize_phase1,
            ),
        }
    }

    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> EthConfigParams {
        self.circuit.config(k, minimum_rows)
    }

    pub fn break_points(&self) -> RlcThreadBreakPoints {
        self.circuit.break_points.borrow().clone()
    }

    pub fn instance_count(&self) -> usize {
        self.assigned_instances.len()
    }

    pub fn instance(&self) -> Vec<F> {
        self.assigned_instances.iter().map(|v| *v.value()).collect()
    }
}

impl<F: Field, FnPhase1: FnSynthesize<F>> Circuit<F> for EthCircuitBuilder<F, FnPhase1> {
    type Config = EthConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params: EthConfigParams =
            serde_json::from_str(&var("ETH_CONFIG_PARAMS").unwrap()).unwrap();
        EthConfig::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // we later `take` the builder, so we need to save this value
        let witness_gen_only = self.circuit.builder.borrow().witness_gen_only();
        let assigned_advices = self.circuit.two_phase_synthesize(&config.mpt, &mut layouter);

        if !witness_gen_only {
            // expose public instances
            let mut layouter = layouter.namespace(|| "expose");
            for (i, instance) in self.assigned_instances.iter().enumerate() {
                let cell = instance.cell.unwrap();
                let (cell, _) = assigned_advices
                    .get(&(cell.context_id, cell.offset))
                    .expect("instance not assigned");
                layouter.constrain_instance(*cell, config.instance, i);
            }
        }
        Ok(())
    }
}

#[cfg(feature = "aggregation")]
impl<F: Field, FnPhase1: FnSynthesize<F>> snark_verifier_sdk::CircuitExt<F>
    for EthCircuitBuilder<F, FnPhase1>
{
    fn num_instance(&self) -> Vec<usize> {
        vec![self.instance_count()]
    }
    fn instances(&self) -> Vec<Vec<F>> {
        vec![self.instance()]
    }
}

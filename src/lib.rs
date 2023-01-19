#![feature(int_log)]

pub mod block_header;
pub mod keccak;
pub mod mpt;
pub mod rlp;
pub mod storage;
pub mod util;

#[cfg(feature = "providers")]
pub mod providers;

use crate::rlp::{
    rlc::{RlcChip, RlcConfig},
    RlpChip, RlpConfig,
};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig},
    halo2_proofs::{
        self,
        circuit::Value,
        plonk::{Column, ConstraintSystem, Instance},
    },
    Context,
};
use keccak::KeccakChip;
use mpt::{MPTChip, MPTConfig};
use util::EthConfigParams;
pub use zkevm_keccak::util::eth_types::Field;
use zkevm_keccak::KeccakConfig;

#[derive(Clone, Copy, Debug, PartialEq)]
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
/// Config shared for block header and storage proof circuits
pub struct EthConfig<F: Field> {
    pub mpt: MPTConfig<F>,
    pub instance: Column<Instance>,
}

impl<F: Field> EthConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        params: impl Into<EthConfigParams>,
        context_id: usize,
    ) -> Self {
        let mpt = MPTConfig::configure(meta, params.into(), context_id);
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
}

#[derive(Clone, Debug)]
pub struct EthChip<'v, F: Field> {
    pub mpt: MPTChip<'v, F>,
}

impl<'v, F: Field> EthChip<'v, F> {
    pub fn new(config: EthConfig<F>, gamma: Value<F>) -> Self {
        Self { mpt: MPTChip::new(config.mpt, gamma) }
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        self.mpt.gate()
    }
    pub fn range(&self) -> &RangeConfig<F> {
        self.mpt.range()
    }
    pub fn rlc(&self) -> &RlcChip<'v, F> {
        self.mpt.rlc()
    }
    pub fn rlp(&self) -> &RlpChip<'v, F> {
        self.mpt.rlp()
    }
    pub fn keccak(&self) -> &KeccakChip<'v, F> {
        self.mpt.keccak()
    }
    pub fn keccak_mut(&mut self) -> &mut KeccakChip<'v, F> {
        &mut self.mpt.keccak
    }

    pub fn get_challenge(&mut self, ctx: &mut Context<F>) {
        self.mpt.get_challenge(ctx);
    }

    /// Call this to finalize `FirstPhase`
    /// Generates and assign witnesses for keccak.
    /// Assign cells to range check to special advice columns with lookup enabled.
    pub fn assign_phase0(&mut self, ctx: &mut Context<F>) {
        self.mpt.keccak.assign_phase0(&mut ctx.region);
        self.range().finalize(ctx);
    }

    /// Call this at the beginning of `SecondPhase` if you want to use keccak RLCs for other purposes
    pub fn keccak_assign_phase1(&mut self, ctx: &mut Context<'v, F>) {
        self.mpt.keccak.assign_phase1(ctx, &mut self.mpt.rlp.rlc, &self.mpt.rlp.range);
    }
}

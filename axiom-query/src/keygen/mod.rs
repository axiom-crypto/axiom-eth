//! Module with utility functions to generate proving keys and verifying keys for production circuits.

use std::path::Path;

use axiom_eth::{
    halo2_proofs::plonk::ProvingKey, halo2curves::bn256::G1Affine,
    utils::build_utils::pinning::aggregation::AggTreeId,
};
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};

use self::{
    agg::{
        axiom_agg_1::RecursiveAxiomAgg1Intent, axiom_agg_2::RecursiveAxiomAgg2Intent,
        common::AggTreePinning, single_type::*, subquery_agg::RecursiveSubqueryAggIntent,
        SupportedAggPinning,
    },
    shard::{keccak::ShardIntentKeccak, *},
};

pub mod agg;
pub mod shard;

pub type CircuitId = String;

#[derive(Serialize, Deserialize)]
#[enum_dispatch(ProvingKeySerializer)]
pub enum SupportedRecursiveIntent {
    Subquery(SupportedIntentTreeSingleType),
    VerifyCompute(CircuitIntentVerifyCompute),
    SubqueryAgg(RecursiveSubqueryAggIntent),
    Keccak(IntentTreeSingleType<ShardIntentKeccak>),
    AxiomAgg1(RecursiveAxiomAgg1Intent),
    AxiomAgg2(RecursiveAxiomAgg2Intent),
}

/// ** !! IMPORTANT !! **
/// Enum names are used to deserialize the pinning file. Please be careful if you need renaming.
#[derive(Serialize, Deserialize, Clone)]
#[enum_dispatch(AggTreePinning)]
pub enum SupportedPinning {
    Shard(SupportedShardPinning),
    Agg(SupportedAggPinning),
}

// We only serialize to [SupportedPinning] so the JSON will have the name of the pinning in it.
/// Trait specific to this crate for keygen since it uses enum_dispatch and must return a pinning in enum [SupportedPinning].
#[enum_dispatch]
pub trait ProvingKeySerializer: Sized {
    /// Recursively creates and serializes proving keys and pinnings.
    ///
    /// Computes `circuit_id` as the blake3 hash of the halo2 VerifyingKey written to bytes. Writes proving key to `circuit_id.pk`, verifying key to `circuit_id.vk` and pinning to `circuit_id.json` in the `data_dir` directory.
    ///
    /// Returns the `circuit_id, proving_key, pinning`.
    fn create_and_serialize_proving_key(
        self,
        params_dir: &Path,
        data_dir: &Path,
    ) -> anyhow::Result<(AggTreeId, ProvingKey<G1Affine>, SupportedPinning)>;
}

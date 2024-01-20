use std::iter;

use axiom_codec::HiLo;
use axiom_eth::utils::snark_verifier::EnhancedSnark;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputAxiomAggregation1 {
    pub snark_verify_compute: EnhancedSnark,
    pub snark_subquery_agg: EnhancedSnark,
    /// Snark of aggregation circuit for keccak component shards
    pub snark_keccak_agg: EnhancedSnark,
}

const NUM_LOGICAL_INSTANCE_NO_PAYEE: usize = 1 + 1 + 2 + 2 + 2 + 2;
pub const NUM_LOGICAL_INSTANCE_WITH_PAYEE: usize = NUM_LOGICAL_INSTANCE_NO_PAYEE + 1;
pub const FINAL_AGG_VKEY_HASH_IDX: usize = NUM_LOGICAL_INSTANCE_NO_PAYEE - 1;

/// The public instances of the AxiomAggregation1 and AxiomAggregation2 circuits,
/// excluding the accumulator at the beginning.
/// The `payee` field is only provided and exposed in AxiomAggregation2.
/// We use the same struct for both circuits for uniformity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct LogicalPublicInstanceAxiomAggregation<T> {
    pub source_chain_id: T,
    pub compute_results_hash: HiLo<T>,
    pub query_hash: HiLo<T>,
    pub query_schema: HiLo<T>,
    pub blockhash_mmr_keccak: HiLo<T>,
    pub agg_vkey_hash: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payee: Option<T>,
}

impl<T: Copy> LogicalPublicInstanceAxiomAggregation<T> {
    pub fn flatten(&self) -> Vec<T> {
        iter::once(self.source_chain_id)
            .chain(self.compute_results_hash.hi_lo())
            .chain(self.query_hash.hi_lo())
            .chain(self.query_schema.hi_lo())
            .chain(self.blockhash_mmr_keccak.hi_lo())
            .chain([self.agg_vkey_hash])
            .chain(self.payee)
            .collect()
    }
}

impl<T: Copy> TryFrom<Vec<T>> for LogicalPublicInstanceAxiomAggregation<T> {
    type Error = anyhow::Error;
    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.len() != NUM_LOGICAL_INSTANCE_NO_PAYEE
            && value.len() != NUM_LOGICAL_INSTANCE_NO_PAYEE + 1
        {
            anyhow::bail!("invalid number of instances");
        }
        let source_chain_id = value[0];
        let compute_results_hash = HiLo::from_hi_lo([value[1], value[2]]);
        let query_hash = HiLo::from_hi_lo([value[3], value[4]]);
        let query_schema = HiLo::from_hi_lo([value[5], value[6]]);
        let blockhash_mmr_keccak = HiLo::from_hi_lo([value[7], value[8]]);
        let agg_vkey_hash = value[9];
        let payee = value.get(NUM_LOGICAL_INSTANCE_NO_PAYEE).copied();
        Ok(Self {
            source_chain_id,
            compute_results_hash,
            query_hash,
            query_schema,
            blockhash_mmr_keccak,
            agg_vkey_hash,
            payee,
        })
    }
}

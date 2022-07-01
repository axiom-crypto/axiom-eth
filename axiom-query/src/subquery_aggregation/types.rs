use std::iter;
use std::marker::PhantomData;

use anyhow::anyhow;
use axiom_codec::HiLo;
use axiom_eth::{
    halo2_base::AssignedValue,
    impl_flatten_conversion,
    utils::{
        component::{types::LogicalEmpty, ComponentType, ComponentTypeId, LogicalResult},
        snark_verifier::EnhancedSnark,
    },
};
use serde::{Deserialize, Serialize};

pub(crate) type F = axiom_eth::halo2curves::bn256::Fr;

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputSubqueryAggregation {
    /// Header snark always required
    pub snark_header: EnhancedSnark,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub snark_account: Option<EnhancedSnark>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snark_storage: Option<EnhancedSnark>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snark_solidity_mapping: Option<EnhancedSnark>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snark_tx: Option<EnhancedSnark>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snark_receipt: Option<EnhancedSnark>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snark_ecdsa: Option<EnhancedSnark>,

    /// The keccak commit is provided as a public input.
    /// The SubqueryAggregation circuit will check that all subquery component circuits use the same promise commit for keccak.
    /// It will not check the promise commit itself. That will be done by AxiomAggregation1, which aggregates this SubqueryAggregation circuit.
    pub promise_commit_keccak: F,

    /// Results root snark always required
    pub snark_results_root: EnhancedSnark,
}

pub struct ComponentTypeSubqueryAgg {
    _phatnom: PhantomData<F>,
}
impl ComponentType<F> for ComponentTypeSubqueryAgg {
    type InputValue = LogicalEmpty<F>;
    type InputWitness = LogicalEmpty<AssignedValue<F>>;
    type OutputValue = LogicalEmpty<F>;
    type OutputWitness = LogicalEmpty<AssignedValue<F>>;
    type LogicalInput = LogicalEmpty<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-query:ComponentTypeSubqueryAgg".to_string()
    }

    fn logical_result_to_virtual_rows_impl(
        _ins: &LogicalResult<F, Self>,
    ) -> Vec<(Self::InputValue, Self::OutputValue)> {
        unreachable!()
    }
    fn logical_input_to_virtual_rows_impl(_li: &Self::LogicalInput) -> Vec<Self::InputValue> {
        unreachable!()
    }
}

/// The public instances **without** the accumulator
const FIELD_SIZE_PUBLIC_INSTANCES: [usize; 6] = [
    9999, // promise_keccak
    9999, // agg_vk_hash
    9999, // results_root_poseidon
    9999, // commit_subquery_hashes
    128, 128, // mmr_keccak
];
pub const SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX: usize = 1;

/// Public instances **without** the accumulator (accumulator is 12 field elements)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogicalPublicInstanceSubqueryAgg<T> {
    pub promise_keccak: T,
    pub agg_vkey_hash: T,
    pub results_root_poseidon: T,
    pub commit_subquery_hashes: T,
    pub mmr_keccak: HiLo<T>,
}

impl<T> TryFrom<Vec<T>> for LogicalPublicInstanceSubqueryAgg<T> {
    type Error = anyhow::Error;
    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        let [promise_keccak, agg_vkey_hash, results_root_poseidon, commit_subquery_hashes, mmr_hi, mmr_lo] =
            value
                .try_into()
                .map_err(|_| anyhow!("LogicalPublicInstanceSubqueryAgg invalid length"))?;
        Ok(Self {
            promise_keccak,
            agg_vkey_hash,
            results_root_poseidon,
            commit_subquery_hashes,
            mmr_keccak: HiLo::from_hi_lo([mmr_hi, mmr_lo]),
        })
    }
}

impl<T: Copy> LogicalPublicInstanceSubqueryAgg<T> {
    pub fn flatten(&self) -> Vec<T> {
        iter::empty()
            .chain([self.promise_keccak, self.agg_vkey_hash])
            .chain([self.results_root_poseidon, self.commit_subquery_hashes])
            .chain(self.mmr_keccak.hi_lo())
            .collect()
    }
}

// This is not used:
impl_flatten_conversion!(LogicalPublicInstanceSubqueryAgg, FIELD_SIZE_PUBLIC_INSTANCES);

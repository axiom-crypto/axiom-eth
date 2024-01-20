//! Types are separated into:
//! - Circuit metadata that along with the circuit type determines the circuit configuration completely.
//! - Human readable _logical_ input and output to the circuit. These include private inputs and outputs that are only commited to in the public output.
//! - The in-circuit formatted versions of logical inputs and outputs. These include formatting in terms of field elements and accounting for all lengths needing to be fixed at compile time.
//!   - We then provide conversion functions from human-readable to circuit formats.
//! - This circuit has no public instances (IO) other than the circuit's own component commitment and the promise commitments from any component calls.
use std::marker::PhantomData;

use axiom_codec::{
    types::{field_elements::FieldStorageSubquery, native::StorageSubquery},
    HiLo,
};
use axiom_eth::{
    halo2_base::AssignedValue,
    impl_fix_len_call_witness,
    providers::storage::json_to_mpt_input,
    storage::circuit::EthStorageInput,
    utils::{
        build_utils::dummy::DummyFrom,
        component::{circuit::CoreBuilderInput, ComponentType, ComponentTypeId, LogicalResult},
    },
};
use ethers_core::types::{EIP1186ProofResponse, H256};
use serde::{Deserialize, Serialize};

use crate::utils::codec::AssignedStorageSubquery;
use crate::{
    components::subqueries::{
        account::types::GENESIS_ADDRESS_0_ACCOUNT_PROOF, common::OutputSubqueryShard,
    },
    Field,
};

use super::circuit::CoreParamsStorageSubquery;

/// Identifier for the component type of this component circuit
pub struct ComponentTypeStorageSubquery<F: Field>(PhantomData<F>);

/// Human readable.
/// The output value of any storage subquery is always `bytes32` right now.
pub type OutputStorageShard = OutputSubqueryShard<StorageSubquery, H256>;

/// Circuit input for a shard of Storage subqueries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInputStorageShard<F: Field> {
    /// Enriched subquery requests
    pub requests: Vec<CircuitInputStorageSubquery>,
    pub _phantom: PhantomData<F>,
}

/// Circuit input for a single Storage subquery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInputStorageSubquery {
    /// The block number to access the storage state at.
    pub block_number: u64,
    /// Storage proof formatted as MPT input. It will contain the account address.
    /// ### Warning
    /// `proof.acct_pf` will be empty and `proof` will **not** have state_root set.
    pub proof: EthStorageInput,
}

impl<F: Field> DummyFrom<CoreParamsStorageSubquery> for CircuitInputStorageShard<F> {
    fn dummy_from(core_params: CoreParamsStorageSubquery) -> Self {
        let CoreParamsStorageSubquery { capacity, max_trie_depth } = core_params;
        let request = {
            let pf: EIP1186ProofResponse =
                serde_json::from_str(GENESIS_ADDRESS_0_ACCOUNT_PROOF).unwrap();
            let proof = json_to_mpt_input(pf, 0, max_trie_depth);
            CircuitInputStorageSubquery { block_number: 0, proof }
        };
        Self { requests: vec![request; capacity], _phantom: PhantomData }
    }
}

/// The output value of any storage subquery is always `bytes32` right now.
/// Vector has been resized to the capacity.
pub type CircuitOutputStorageShard<T> = OutputSubqueryShard<FieldStorageSubquery<T>, HiLo<T>>;

impl_fix_len_call_witness!(
    FieldStorageSubqueryCall,
    FieldStorageSubquery,
    ComponentTypeStorageSubquery
);

// ===== The storage component has no public instances other than the component commitment and promise commitments from external component calls =====

impl<F: Field> ComponentType<F> for ComponentTypeStorageSubquery<F> {
    type InputValue = FieldStorageSubquery<F>;
    type InputWitness = AssignedStorageSubquery<F>;
    type OutputValue = HiLo<F>;
    type OutputWitness = HiLo<AssignedValue<F>>;
    type LogicalInput = FieldStorageSubquery<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-query:ComponentTypeStorageSubquery".to_string()
    }

    fn logical_result_to_virtual_rows_impl(
        ins: &LogicalResult<F, Self>,
    ) -> Vec<(Self::InputValue, Self::OutputValue)> {
        vec![(ins.input, ins.output)]
    }
    fn logical_input_to_virtual_rows_impl(li: &Self::LogicalInput) -> Vec<Self::InputValue> {
        vec![*li]
    }
}

impl<F: Field> From<OutputStorageShard> for CircuitOutputStorageShard<F> {
    fn from(output: OutputStorageShard) -> Self {
        output.convert_into()
    }
}

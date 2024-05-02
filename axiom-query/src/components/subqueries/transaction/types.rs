//! Types are separated into:
//! - Circuit metadata that along with the circuit type determines the circuit configuration completely.
//! - Human readable _logical_ input and output to the circuit. These include private inputs and outputs that are only commited to in the public output.
//! - The in-circuit formatted versions of logical inputs and outputs. These include formatting in terms of field elements and accounting for all lengths needing to be fixed at compile time.
//!   - We then provide conversion functions from human-readable to circuit formats.
//! - This circuit has no public instances (IO) other than the circuit's own component commitment and the promise commitments from any component calls.
use std::{marker::PhantomData, sync::Arc};

use axiom_codec::{
    types::{field_elements::FieldTxSubquery, native::TxSubquery},
    HiLo,
};
use axiom_eth::{
    halo2_base::AssignedValue,
    impl_fix_len_call_witness,
    mpt::MPTInput,
    transaction::{calc_max_val_len as tx_calc_max_val_len, EthTransactionProof},
    utils::{
        build_utils::dummy::DummyFrom,
        component::{circuit::CoreBuilderInput, ComponentType, ComponentTypeId, LogicalResult},
    },
};
use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use ethers_core::types::{Transaction, H256};
use hasher::HasherKeccak;
use serde::{Deserialize, Serialize};

use crate::{
    components::subqueries::common::OutputSubqueryShard, utils::codec::AssignedTxSubquery, Field,
};

use super::circuit::CoreParamsTxSubquery;

/// Identifier for the component type of this component circuit
pub struct ComponentTypeTxSubquery<F: Field>(PhantomData<F>);

/// Human readable.
/// The output value of any transaction subquery is always `bytes32` right now.
pub type OutputTxShard = OutputSubqueryShard<TxSubquery, H256>;

/// Circuit input for a shard of Tx subqueries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInputTxShard<F: Field> {
    /// Enriched subquery requests
    pub requests: Vec<CircuitInputTxSubquery>,
    pub _phantom: PhantomData<F>,
}

/// Circuit input for a single Tx subquery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInputTxSubquery {
    /// The block number to access the storage state at.
    pub block_number: u64,
    /// Transaction proof formatted as [axiom_eth::mpt::MPTInput]. Contains the transaction index.
    pub proof: EthTransactionProof,
    /// Special index to specify what subquery value to extract from the transaction.
    pub field_or_calldata_idx: u32,
}

impl<F: Field> DummyFrom<CoreParamsTxSubquery> for CircuitInputTxShard<F> {
    fn dummy_from(core_params: CoreParamsTxSubquery) -> Self {
        let CoreParamsTxSubquery { chip_params, capacity, max_trie_depth } = core_params;
        let mut trie =
            PatriciaTrie::new(Arc::new(MemoryDB::new(true)), Arc::new(HasherKeccak::new()));
        let tx = Transaction::default();
        let tx_rlp = tx.rlp().to_vec();
        trie.insert(vec![0x80], tx_rlp.clone()).unwrap();
        let mpt_input = MPTInput {
            path: (&[0x80]).into(),
            value: tx_rlp,
            root_hash: Default::default(),
            proof: trie.get_proof(&[0x80]).unwrap(),
            value_max_byte_len: tx_calc_max_val_len(
                chip_params.max_data_byte_len,
                chip_params.max_access_list_len,
                chip_params.enable_types,
            ),
            max_depth: max_trie_depth,
            slot_is_empty: false,
            max_key_byte_len: 3,
            key_byte_len: Some(1),
        };
        let tx_pf = EthTransactionProof { tx_index: 0, proof: mpt_input };
        let dummy_subquery =
            CircuitInputTxSubquery { block_number: 0, proof: tx_pf, field_or_calldata_idx: 0 };
        Self { requests: vec![dummy_subquery; capacity], _phantom: PhantomData }
    }
}

/// The output value of any storage subquery is always `bytes32` right now.
/// Vector has been resized to the capacity.
pub type CircuitOutputTxShard<T> = OutputSubqueryShard<FieldTxSubquery<T>, HiLo<T>>;

impl_fix_len_call_witness!(FieldTxSubqueryCall, FieldTxSubquery, ComponentTypeTxSubquery);

// ===== The storage component has no public instances other than the component commitment and promise commitments from external component calls =====

impl<F: Field> ComponentType<F> for ComponentTypeTxSubquery<F> {
    type InputValue = FieldTxSubquery<F>;
    type InputWitness = AssignedTxSubquery<F>;
    type OutputValue = HiLo<F>;
    type OutputWitness = HiLo<AssignedValue<F>>;
    type LogicalInput = FieldTxSubquery<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-query:ComponentTypeTxSubquery".to_string()
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

impl<F: Field> From<OutputTxShard> for CircuitOutputTxShard<F> {
    fn from(output: OutputTxShard) -> Self {
        output.convert_into()
    }
}

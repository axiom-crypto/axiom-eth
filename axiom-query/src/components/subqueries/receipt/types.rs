//! Types are separated into:
//! - Circuit metadata that along with the circuit type determines the circuit configuration completely.
//! - Human readable _logical_ input and output to the circuit. These include private inputs and outputs that are only commited to in the public output.
//! - The in-circuit formatted versions of logical inputs and outputs. These include formatting in terms of field elements and accounting for all lengths needing to be fixed at compile time.
//!   - We then provide conversion functions from human-readable to circuit formats.
//! - This circuit has no public instances (IO) other than the circuit's own component commitment and the promise commitments from any component calls.
use std::{marker::PhantomData, sync::Arc};

use axiom_codec::{
    types::{field_elements::FieldReceiptSubquery, native::ReceiptSubquery},
    HiLo,
};
use axiom_eth::{
    halo2_base::AssignedValue,
    impl_fix_len_call_witness,
    mpt::MPTInput,
    providers::receipt::{get_receipt_rlp, TransactionReceipt},
    receipt::{calc_max_val_len as rc_calc_max_val_len, EthReceiptInput},
    utils::{
        build_utils::dummy::DummyFrom,
        component::{circuit::CoreBuilderInput, ComponentType, ComponentTypeId, LogicalResult},
    },
};
use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use ethers_core::types::H256;
use hasher::HasherKeccak;
use serde::{Deserialize, Serialize};

use crate::{
    components::subqueries::common::OutputSubqueryShard, utils::codec::AssignedReceiptSubquery,
    Field,
};

use super::circuit::CoreParamsReceiptSubquery;

/// Identifier for the component type of this component circuit
pub struct ComponentTypeReceiptSubquery<F: Field>(PhantomData<F>);

/// Human readable.
/// The output value of any transaction subquery is always `bytes32` right now.
pub type OutputReceiptShard = OutputSubqueryShard<ReceiptSubquery, H256>;

/// Circuit input for a shard of Receipt subqueries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInputReceiptShard<F: Field> {
    /// Enriched subquery requests
    pub requests: Vec<CircuitInputReceiptSubquery>,
    pub _phantom: PhantomData<F>,
}

/// Circuit input for a single Receipt subquery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInputReceiptSubquery {
    /// The block number to access the storage state at.
    pub block_number: u64,
    /// Transaction proof formatted as [axiom_eth::mpt::MPTInput]. Contains the transaction index.
    pub proof: EthReceiptInput,
    /// Special index to specify what subquery value to extract from the transaction.
    pub field_or_log_idx: u32,
    pub topic_or_data_or_address_idx: u32,
    pub event_schema: H256,
}

impl<F: Field> DummyFrom<CoreParamsReceiptSubquery> for CircuitInputReceiptShard<F> {
    fn dummy_from(core_params: CoreParamsReceiptSubquery) -> Self {
        let CoreParamsReceiptSubquery { chip_params, capacity, max_trie_depth } = core_params;
        let mut trie =
            PatriciaTrie::new(Arc::new(MemoryDB::new(true)), Arc::new(HasherKeccak::new()));
        let rc = TransactionReceipt { status: Some(0x1.into()), ..Default::default() };
        let rc_rlp = get_receipt_rlp(&rc).unwrap().to_vec();
        trie.insert(vec![0x80], rc_rlp.clone()).unwrap();
        let mpt_input = MPTInput {
            path: (&[0x80]).into(),
            value: rc_rlp,
            root_hash: Default::default(),
            proof: trie.get_proof(&[0x80]).unwrap(),
            value_max_byte_len: rc_calc_max_val_len(
                chip_params.max_data_byte_len,
                chip_params.max_log_num,
                chip_params.topic_num_bounds,
            ),
            max_depth: max_trie_depth,
            slot_is_empty: false,
            max_key_byte_len: 3,
            key_byte_len: Some(1),
        };
        let rc_pf = EthReceiptInput { idx: 0, proof: mpt_input };
        let dummy_subquery = CircuitInputReceiptSubquery {
            block_number: 0,
            proof: rc_pf,
            field_or_log_idx: 0,
            topic_or_data_or_address_idx: 0,
            event_schema: H256::zero(),
        };
        Self { requests: vec![dummy_subquery; capacity], _phantom: PhantomData }
    }
}

/// The output value of any storage subquery is always `bytes32` right now.
/// Vector has been resized to the capacity.
pub type CircuitOutputReceiptShard<T> = OutputSubqueryShard<FieldReceiptSubquery<T>, HiLo<T>>;

impl_fix_len_call_witness!(
    FieldReceiptSubqueryCall,
    FieldReceiptSubquery,
    ComponentTypeReceiptSubquery
);

// ===== The storage component has no public instances other than the component commitment and promise commitments from external component calls =====

impl<F: Field> ComponentType<F> for ComponentTypeReceiptSubquery<F> {
    type InputValue = FieldReceiptSubquery<F>;
    type InputWitness = AssignedReceiptSubquery<F>;
    type OutputValue = HiLo<F>;
    type OutputWitness = HiLo<AssignedValue<F>>;
    type LogicalInput = FieldReceiptSubquery<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-query:ComponentTypeReceiptSubquery".to_string()
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

impl<F: Field> From<OutputReceiptShard> for CircuitOutputReceiptShard<F> {
    fn from(output: OutputReceiptShard) -> Self {
        output.convert_into()
    }
}

//! Types are separated into:
//! - Circuit metadata that along with the circuit type determines the circuit configuration completely.
//! - Human readable _logical_ input and output to the circuit. These include private inputs and outputs that are only commited to in the public output.
//! - The in-circuit formatted versions of logical inputs and outputs. These include formatting in terms of field elements and accounting for all lengths needing to be fixed at compile time.
//!   - We then provide conversion functions from human-readable to circuit formats.
//! - A struct for the public instances (IO) of the circuit, excluding the circuit's own component commitment and the promise commitments from any component calls.
//!   - We then specify [TryFrom] and [From] implementations to describe how to "flatten" the public instance struct into a 1d array of field elements.
use std::marker::PhantomData;

use axiom_codec::{
    types::{field_elements::FieldHeaderSubquery, native::HeaderSubquery},
    HiLo,
};
use axiom_eth::{
    block_header::{get_block_header_rlp_max_lens_from_extra, GENESIS_BLOCK_RLP},
    halo2_base::AssignedValue,
    impl_fix_len_call_witness,
    utils::{
        build_utils::dummy::DummyFrom,
        component::{
            circuit::CoreBuilderInput,
            types::{FixLenLogical, Flatten},
            ComponentType, ComponentTypeId, LogicalResult,
        },
    },
};
use ethers_core::types::H256;
use serde::{Deserialize, Serialize};

use crate::Field;
use crate::{
    components::subqueries::common::OutputSubqueryShard, utils::codec::AssignedHeaderSubquery,
};

use super::{circuit::CoreParamsHeaderSubquery, MMR_MAX_NUM_PEAKS};

/// Identifier for the component type of this component circuit
pub struct ComponentTypeHeaderSubquery<F: Field>(PhantomData<F>);

/// Human readable
pub type OutputHeaderShard = OutputSubqueryShard<HeaderSubquery, H256>;

/// Circuit input for a shard of Header subqueries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInputHeaderShard<F: Field> {
    // pub(crate) chain_id: u64,
    /// Merkle Mountain Range of block hashes for blocks `[0, mmr_num_blocks)`, in *increasing* order of peak size. Resized with `H256::zero()` to a fixed max length, known at compile time.
    pub mmr: [H256; MMR_MAX_NUM_PEAKS],
    /// Enriched subquery requests
    pub requests: Vec<CircuitInputHeaderSubquery>,
    pub _phantom: PhantomData<F>,
}

/// Circuit input for a single Header subquery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInputHeaderSubquery {
    /// The full RLP encoded block header, resized to a specified `header_rlp_max_bytes`.
    /// Length is known at compile time.
    pub header_rlp: Vec<u8>,
    /// `mmr_proof` is a Merkle proof of this header's `block_hash` into `mmr`.
    pub mmr_proof: [H256; MMR_MAX_NUM_PEAKS - 1],
    pub field_idx: u32,
}

impl<F: Field> DummyFrom<CoreParamsHeaderSubquery> for CircuitInputHeaderShard<F> {
    fn dummy_from(core_params: CoreParamsHeaderSubquery) -> Self {
        let CoreParamsHeaderSubquery { max_extra_data_bytes, capacity } = core_params;

        let (header_rlp_max_bytes, _) =
            get_block_header_rlp_max_lens_from_extra(max_extra_data_bytes);

        let mut header_rlp = GENESIS_BLOCK_RLP.to_vec();
        header_rlp.resize(header_rlp_max_bytes, 0);
        let input_subquery = CircuitInputHeaderSubquery {
            header_rlp,
            mmr_proof: [H256::zero(); MMR_MAX_NUM_PEAKS - 1],
            field_idx: 0,
        };

        CircuitInputHeaderShard {
            mmr: [H256::zero(); MMR_MAX_NUM_PEAKS],
            requests: vec![input_subquery; capacity],
            _phantom: PhantomData,
        }
    }
}

/// The output value of any header subquery is always `bytes32` right now.
/// Vector has been resized to the capacity.
pub type CircuitOutputHeaderShard<T> = OutputSubqueryShard<FieldHeaderSubquery<T>, HiLo<T>>;

impl_fix_len_call_witness!(
    FieldHeaderSubqueryCall,
    FieldHeaderSubquery,
    ComponentTypeHeaderSubquery
);

/// Size in bits of public instances, excluding component commitments
const BITS_PER_PUBLIC_INSTANCE: [usize; 2] = [128, 128];
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalPublicInstanceHeader<T: Copy> {
    pub mmr_keccak: HiLo<T>,
}

impl<F: Field> ComponentType<F> for ComponentTypeHeaderSubquery<F> {
    type InputValue = FieldHeaderSubquery<F>;
    type InputWitness = AssignedHeaderSubquery<F>;
    type OutputValue = HiLo<F>;
    type OutputWitness = HiLo<AssignedValue<F>>;
    type LogicalInput = FieldHeaderSubquery<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-query:ComponentTypeHeaderSubquery".to_string()
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

impl<F: Field> From<OutputHeaderShard> for CircuitOutputHeaderShard<F> {
    fn from(output: OutputHeaderShard) -> Self {
        output.convert_into()
    }
}

// ============== LogicalPublicInstanceHeader ==============
impl<T: Copy> TryFrom<Vec<T>> for LogicalPublicInstanceHeader<T> {
    type Error = anyhow::Error;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.len() != BITS_PER_PUBLIC_INSTANCE.len() {
            return Err(anyhow::anyhow!("incorrect length"));
        }
        Ok(Self { mmr_keccak: HiLo::from_hi_lo([value[0], value[1]]) })
    }
}

impl<T: Copy> TryFrom<Flatten<T>> for LogicalPublicInstanceHeader<T> {
    type Error = anyhow::Error;

    fn try_from(value: Flatten<T>) -> Result<Self, Self::Error> {
        if value.field_size != BITS_PER_PUBLIC_INSTANCE {
            return Err(anyhow::anyhow!("invalid field size"));
        }
        value.fields.try_into()
    }
}
impl<T: Copy> From<LogicalPublicInstanceHeader<T>> for Flatten<T> {
    fn from(val: LogicalPublicInstanceHeader<T>) -> Self {
        Flatten { fields: val.mmr_keccak.hi_lo().to_vec(), field_size: &BITS_PER_PUBLIC_INSTANCE }
    }
}
impl<T: Copy> FixLenLogical<T> for LogicalPublicInstanceHeader<T> {
    fn get_field_size() -> &'static [usize] {
        &BITS_PER_PUBLIC_INSTANCE
    }
}

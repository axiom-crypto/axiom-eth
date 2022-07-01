//! Types are separated into:
//! - Circuit metadata that along with the circuit type determines the circuit configuration completely.
//! - Human readable _logical_ input and output to the circuit. These include private inputs and outputs that are only commited to in the public output.
//! - The in-circuit formatted versions of logical inputs and outputs. These include formatting in terms of field elements and accounting for all lengths needing to be fixed at compile time.
//!   - We then provide conversion functions from human-readable to circuit formats.
//! - This circuit has no public instances (IO) other than the circuit's own component commitment and the promise commitments from any component calls.
use std::marker::PhantomData;

use axiom_codec::{
    types::{
        field_elements::FieldSolidityNestedMappingSubquery, native::SolidityNestedMappingSubquery,
    },
    HiLo,
};
use axiom_eth::{
    halo2_base::AssignedValue,
    impl_fix_len_call_witness,
    utils::{
        build_utils::dummy::DummyFrom,
        component::{circuit::CoreBuilderInput, ComponentType, ComponentTypeId, LogicalResult},
    },
};
use ethers_core::types::H256;
use serde::{Deserialize, Serialize};

use crate::{
    components::subqueries::common::OutputSubqueryShard,
    utils::codec::AssignedSolidityNestedMappingSubquery, Field, RawField,
};

use super::circuit::CoreParamsSolidityNestedMappingSubquery;

/// Identifier for the component type of this component circuit
pub struct ComponentTypeSolidityNestedMappingSubquery<F: Field>(PhantomData<F>);

/// Human readable.
/// The output value of any solidity nested mapping subquery is always `bytes32` right now.
pub type OutputSolidityNestedMappingShard =
    OutputSubqueryShard<SolidityNestedMappingSubquery, H256>;

/// Circuit input for a shard of Solidity Nested Mapping subqueries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInputSolidityNestedMappingShard<F: RawField> {
    /// Enriched subquery requests
    pub requests: Vec<FieldSolidityNestedMappingSubquery<F>>,
}

impl<F: Field> DummyFrom<CoreParamsSolidityNestedMappingSubquery>
    for CircuitInputSolidityNestedMappingShard<F>
{
    fn dummy_from(core_params: CoreParamsSolidityNestedMappingSubquery) -> Self {
        let CoreParamsSolidityNestedMappingSubquery { capacity } = core_params;
        let dummy_subquery =
            FieldSolidityNestedMappingSubquery { mapping_depth: F::ONE, ..Default::default() };
        Self { requests: vec![dummy_subquery; capacity] }
    }
}

/// The output value of any storage subquery is always `bytes32` right now.
/// Vector has been resized to the capacity.
pub type CircuitOutputSolidityNestedMappingShard<T> =
    OutputSubqueryShard<FieldSolidityNestedMappingSubquery<T>, HiLo<T>>;

impl_fix_len_call_witness!(
    FieldSolidityNestedMappingSubqueryCall,
    FieldSolidityNestedMappingSubquery,
    ComponentTypeSolidityNestedMappingSubquery
);

// ===== This component has no public instances other than the output commitment and promise commitments from external component calls =====

impl<F: Field> ComponentType<F> for ComponentTypeSolidityNestedMappingSubquery<F> {
    type InputValue = FieldSolidityNestedMappingSubquery<F>;
    type InputWitness = AssignedSolidityNestedMappingSubquery<F>;
    type OutputValue = HiLo<F>;
    type OutputWitness = HiLo<AssignedValue<F>>;
    type LogicalInput = FieldSolidityNestedMappingSubquery<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-query:ComponentTypeSolidityNestedMappingSubquery".to_string()
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

impl<F: Field> From<OutputSolidityNestedMappingShard>
    for CircuitOutputSolidityNestedMappingShard<F>
{
    fn from(output: OutputSolidityNestedMappingShard) -> Self {
        output.convert_into()
    }
}

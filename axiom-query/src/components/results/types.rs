use std::{any::Any, marker::PhantomData};

use anyhow::Result;
use axiom_codec::{
    types::{
        field_elements::{AnySubqueryResult, FlattenedSubqueryResult},
        native::{SubqueryResult, SubqueryType},
    },
    HiLo,
};
use axiom_eth::{
    halo2_base::{
        gates::{GateInstructions, RangeChip},
        AssignedValue,
    },
    impl_flatten_conversion,
    rlc::{chip::RlcChip, circuit::builder::RlcContextPair},
    utils::{
        build_utils::dummy::DummyFrom,
        component::{
            circuit::CoreBuilderInput,
            promise_loader::{
                flatten_witness_to_rlc,
                multi::{ComponentTypeList, RlcAdapter},
            },
            types::{Flatten, LogicalEmpty},
            utils::into_key,
            ComponentType, ComponentTypeId, LogicalResult, PromiseCallWitness,
            TypelessLogicalInput,
        },
        encode_h256_to_hilo,
    },
};
use ethers_core::types::H256;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{components::results::circuit::SubqueryDependencies, Field, RawField};

use super::{
    circuit::CoreParamsResultRoot,
    table::{join::GroupedSubqueryResults, SubqueryResultsTable},
};

/// Component type for ResultsRoot component.
pub struct ComponentTypeResultsRoot<F: Field>(PhantomData<F>);

/// Logic inputs to Data Results and Calculate Subquery Hashes Circuit
///
/// Length of `data_query` fixed at compile time. True number of subqueries is `num_subqueries`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInputResultsRootShard<F: RawField> {
    /// The **ordered** subqueries to be verified, _with_ claimed result values.
    /// This table may have been resized to some fixed length, known at compile time.
    /// The actual subqueries will be the first `num_subqueries` rows of the table.
    pub subqueries: SubqueryResultsTable<F>,
    /// The number of true subqueries in the table.
    pub num_subqueries: F,
}

impl<F: Field> DummyFrom<CoreParamsResultRoot> for CircuitInputResultsRootShard<F> {
    fn dummy_from(core_params: CoreParamsResultRoot) -> Self {
        let subqueries = SubqueryResultsTable {
            rows: vec![FlattenedSubqueryResult::default(); core_params.capacity],
        };
        Self { subqueries, num_subqueries: F::ZERO }
    }
}

/// Lengths of `results` and `subquery_hashes` are always equal.
/// May include padding - `num_subqueries` is the actual number of subqueries.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct LogicOutputResultsRoot {
    pub results: Vec<SubqueryResult>,
    pub subquery_hashes: Vec<H256>,
    pub num_subqueries: usize,
}

/// Lengths of `results` and `subquery_hashes` must be equal.
///
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CircuitOutputResultsRoot<F: RawField> {
    pub results: SubqueryResultsTable<F>,
    pub subquery_hashes: Vec<HiLo<F>>,
    pub num_subqueries: usize,
}

impl<F: RawField> CircuitOutputResultsRoot<F> {
    /// Resize itself to `new_len` by repeating the first row. Crash if the table is empty.
    pub fn resize_with_first(&mut self, new_len: usize) {
        self.results.rows.resize(new_len, self.results.rows[0]);
        self.subquery_hashes.resize(new_len, self.subquery_hashes[0]);
    }
}

// ==== Public Instances ====
// 9999 means that the public instance takes a whole witness.
const NUM_BITS_PER_FE: [usize; 2] = [9999, 9999];
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogicalPublicInstanceResultsRoot<T> {
    pub results_root_poseidon: T,
    pub commit_subquery_hashes: T,
}

// All promise calls made by ResultsRoot component are Virtual: they will be managed by MultiPromiseLoader
// The ResultsRoot component should never to called directly, so it has no virtual table as output.
impl<F: Field> ComponentType<F> for ComponentTypeResultsRoot<F> {
    type InputValue = LogicalEmpty<F>;
    type InputWitness = LogicalEmpty<AssignedValue<F>>;
    type OutputValue = LogicalEmpty<F>;
    type OutputWitness = LogicalEmpty<AssignedValue<F>>;
    type LogicalInput = LogicalEmpty<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-query:ComponentTypeResultsRoot".to_string()
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

impl LogicOutputResultsRoot {
    pub fn new(
        results: Vec<SubqueryResult>,
        subquery_hashes: Vec<H256>,
        num_subqueries: usize,
    ) -> Self {
        assert_eq!(results.len(), subquery_hashes.len());
        Self { results, subquery_hashes, num_subqueries }
    }
}

impl<F: Field> TryFrom<LogicOutputResultsRoot> for CircuitOutputResultsRoot<F> {
    type Error = std::io::Error;
    fn try_from(output: LogicOutputResultsRoot) -> Result<Self, Self::Error> {
        let LogicOutputResultsRoot { results, subquery_hashes, num_subqueries } = output;
        let rows = results
            .into_iter()
            .map(FlattenedSubqueryResult::<F>::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let results = SubqueryResultsTable { rows };
        let subquery_hashes = subquery_hashes
            .into_iter()
            .map(|subquery_hash| encode_h256_to_hilo(&subquery_hash))
            .collect();
        Ok(Self { results, subquery_hashes, num_subqueries })
    }
}

// ============== LogicalPublicInstanceResultsRoot ==============
impl<T: Copy> TryFrom<Vec<T>> for LogicalPublicInstanceResultsRoot<T> {
    type Error = anyhow::Error;

    fn try_from(value: Vec<T>) -> anyhow::Result<Self> {
        let [results_root_poseidon, commit_subquery_hashes] =
            value.try_into().map_err(|_| anyhow::anyhow!("invalid length"))?;
        Ok(Self { results_root_poseidon, commit_subquery_hashes })
    }
}
impl<T: Copy> LogicalPublicInstanceResultsRoot<T> {
    pub fn flatten(&self) -> [T; 2] {
        [self.results_root_poseidon, self.commit_subquery_hashes]
    }
}
impl_flatten_conversion!(LogicalPublicInstanceResultsRoot, NUM_BITS_PER_FE);

// ======== Types for component implementation ==========

/// RLC adapter for MultiPromiseLoader of results root component.
pub struct RlcAdapterResultsRoot<F>(PhantomData<F>);
impl<F: Field> RlcAdapter<F> for RlcAdapterResultsRoot<F> {
    fn to_rlc(
        ctx_pair: RlcContextPair<F>,
        gate: &impl GateInstructions<F>,
        rlc: &RlcChip<F>,
        component_type_id: &ComponentTypeId,
        io_pairs: &[(Flatten<AssignedValue<F>>, Flatten<AssignedValue<F>>)],
    ) -> Vec<AssignedValue<F>> {
        let subquery_type = component_type_id_to_subquery_type::<F>(component_type_id).unwrap();

        let subqueries = GroupedSubqueryResults {
            subquery_type,
            results: io_pairs
                .iter()
                .map(|(i, o)| AnySubqueryResult {
                    subquery: i.fields.clone(),
                    value: o.fields.clone(),
                })
                .collect_vec(),
        };
        subqueries.into_rlc(ctx_pair, gate, rlc).concat()
    }
}

/// Virtual component type for MultiPromiseLoader
pub struct VirtualComponentType<F: Field>(PhantomData<F>);

impl<F: Field> ComponentType<F> for VirtualComponentType<F> {
    type InputValue = FlattenedSubqueryResult<F>;
    type InputWitness = FlattenedSubqueryResult<AssignedValue<F>>;
    type OutputValue = LogicalEmpty<F>;
    type OutputWitness = LogicalEmpty<AssignedValue<F>>;
    type LogicalInput = LogicalEmpty<F>;

    fn get_type_id() -> ComponentTypeId {
        "axiom-query:VirtualComponentTypeResultsRoot".to_string()
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

#[derive(Clone, Copy, Debug)]
pub struct SubqueryResultCall<F: Field>(pub FlattenedSubqueryResult<AssignedValue<F>>);

impl<F: Field> PromiseCallWitness<F> for SubqueryResultCall<F> {
    fn get_component_type_id(&self) -> ComponentTypeId {
        VirtualComponentType::<F>::get_type_id()
    }
    fn get_capacity(&self) -> usize {
        // virtual call so no consumption
        0
    }
    fn to_rlc(
        &self,
        (_, rlc_ctx): RlcContextPair<F>,
        _range_chip: &RangeChip<F>,
        rlc_chip: &RlcChip<F>,
    ) -> AssignedValue<F> {
        flatten_witness_to_rlc(rlc_ctx, rlc_chip, &self.0.into())
    }
    fn to_typeless_logical_input(&self) -> TypelessLogicalInput {
        let f_a: Flatten<AssignedValue<F>> = self.0.into();
        let f_v: Flatten<F> = f_a.into();
        let l_v: FlattenedSubqueryResult<F> = f_v.try_into().unwrap();
        into_key(l_v)
    }
    fn get_mock_output(&self) -> Flatten<F> {
        let output_val: <VirtualComponentType<F> as ComponentType<F>>::OutputValue =
            Default::default();
        output_val.into()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ======== Boilerplate conversions ========

/// Mapping from component type id to subquery type.
pub fn component_type_id_to_subquery_type<F: Field>(
    type_id: &ComponentTypeId,
) -> Option<SubqueryType> {
    // This cannot be static because of <F>
    let type_ids = SubqueryDependencies::<F>::get_component_type_ids();
    type_ids
        .iter()
        .position(|id| id == type_id)
        .map(|i| SubqueryType::try_from(i as u16 + 1).unwrap())
}

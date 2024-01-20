use std::{any::Any, collections::HashMap, fmt::Debug, hash::Hash, marker::PhantomData};

use crate::{Field, RawField};
use getset::Getters;
use halo2_base::{
    gates::{circuit::builder::BaseCircuitBuilder, GateInstructions, RangeChip},
    halo2_proofs::halo2curves::bn256::Fr,
    AssignedValue, Context,
};
use itertools::Itertools;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use static_assertions::assert_impl_all;

use crate::rlc::chip::RlcChip;

use self::{
    promise_loader::{
        comp_loader::{BasicComponentCommiter, ComponentCommiter},
        flatten_witness_to_rlc,
    },
    types::{ComponentPublicInstances, FixLenLogical, Flatten},
    utils::{into_key, try_from_key},
};

pub mod circuit;
pub mod param;
pub mod promise_collector;
pub mod promise_loader;
#[cfg(test)]
mod tests;
pub mod types;
pub mod utils;

pub type ComponentId = u64;
pub type ComponentTypeId = String;
pub const USER_COMPONENT_ID: ComponentId = 0;

/// Unified representation of a logical input of a component type.
/// TODO: Can this be extended to variable length output?
/// In the caller end, there could be multiple formats of promise calls for a component type. e.g.
/// fix/var length array to keccak. But in the receiver end, we only need to know the logical input.
/// In the receiver end, a logical input could take 1(fix len input) or multiple virtual rows(var len).
/// The number of virtual rows a logical input take is "capacity".
pub trait LogicalInputValue<F: Field>:
    Debug + Send + Sync + Clone + Eq + Serialize + DeserializeOwned + 'static
{
    /// Get the capacity of this logical input.
    /// The default implementaion is for the fixed length case.
    fn get_capacity(&self) -> usize;
}
/// A format of a promise call to component type T.
pub trait PromiseCallWitness<F: Field>: Debug + Send + Sync + 'static {
    /// The component type this promise call is for.
    fn get_component_type_id(&self) -> ComponentTypeId;
    /// Get the capacity of this promise call.
    fn get_capacity(&self) -> usize;
    /// Encode the promise call into RLC.
    /// TODO: maybe pass builder here for better flexiability? but constructing chips are slow.
    fn to_rlc(
        &self,
        ctx_pair: (&mut Context<F>, &mut Context<F>),
        range_chip: &RangeChip<F>,
        rlc_chip: &RlcChip<F>,
    ) -> AssignedValue<F>;
    /// Get the logical input of this promise call.
    fn to_typeless_logical_input(&self) -> TypelessLogicalInput;
    /// Get dummy output of this promise call.
    fn get_mock_output(&self) -> Flatten<F>;
    /// Enable downcasting
    fn as_any(&self) -> &dyn Any;
}

/// The flatten version of output of a component.
pub type FlattenVirtualTable<F> = Vec<FlattenVirtualRow<F>>;
/// A flatten virtual row in a virtual table.
pub type FlattenVirtualRow<F> = (Flatten<F>, Flatten<F>);

/// Logical result of a component type.
#[derive(Clone)]
pub struct LogicalResult<F: Field, T: ComponentType<F>> {
    pub input: T::LogicalInput,
    pub output: T::OutputValue,
    pub _marker: PhantomData<F>,
}
impl<F: Field, T: ComponentType<F>> LogicalResult<F, T> {
    /// Create LogicalResult
    pub fn new(input: T::LogicalInput, output: T::OutputValue) -> Self {
        Self { input, output, _marker: PhantomData }
    }
}
impl<F: Field, T: ComponentType<F>> TryFrom<ComponentPromiseResult<F>> for LogicalResult<F, T> {
    type Error = anyhow::Error;
    fn try_from(value: ComponentPromiseResult<F>) -> Result<Self, Self::Error> {
        let (input, output) = value;
        let input = try_from_key::<T::LogicalInput>(&input)?;
        Ok(Self::new(input, T::OutputValue::try_from_raw(output)?))
    }
}
impl<F: Field, T: ComponentType<F>> From<LogicalResult<F, T>> for ComponentPromiseResult<F> {
    fn from(value: LogicalResult<F, T>) -> Self {
        let LogicalResult { input, output, .. } = value;
        (into_key(input), output.into_raw())
    }
}
impl<F: Field, T: ComponentType<F>> From<LogicalResult<F, T>> for Vec<FlattenVirtualRow<F>> {
    fn from(value: LogicalResult<F, T>) -> Self {
        let logical_virtual_rows = T::logical_result_to_virtual_rows(&value);
        logical_virtual_rows
            .into_iter()
            .map(|(input, output)| (input.into(), output.into()))
            .collect_vec()
    }
}
/// Specify the logical types of a component type.
pub trait ComponentType<F: Field>: 'static + Sized {
    type InputValue: FixLenLogical<F>;
    type InputWitness: FixLenLogical<AssignedValue<F>>;
    type OutputValue: FixLenLogical<F>;
    type OutputWitness: FixLenLogical<AssignedValue<F>>;
    type LogicalInput: LogicalInputValue<F>;
    type Commiter: ComponentCommiter<F> = BasicComponentCommiter<F>;

    /// Get ComponentTypeId of this component type.
    fn get_type_id() -> ComponentTypeId;
    /// Get ComponentTypeName for logging/debugging.
    fn get_type_name() -> &'static str {
        std::any::type_name::<Self>()
    }

    /// Wrap logical_result_to_virtual_rows_impl with sanity check.
    fn logical_result_to_virtual_rows(
        ins: &LogicalResult<F, Self>,
    ) -> Vec<(Self::InputValue, Self::OutputValue)> {
        let v_rows = Self::logical_result_to_virtual_rows_impl(ins);
        assert_eq!(v_rows.len(), ins.input.get_capacity());
        v_rows
    }
    /// Convert a logical result to 1 or multiple virtual rows.
    fn logical_result_to_virtual_rows_impl(
        ins: &LogicalResult<F, Self>,
    ) -> Vec<(Self::InputValue, Self::OutputValue)>;

    /// Wrap logical_input_to_virtual_rows_impl with sanity check.
    /// TODO: we are not using this.
    fn logical_input_to_virtual_rows(li: &Self::LogicalInput) -> Vec<Self::InputValue> {
        let v_rows = Self::logical_input_to_virtual_rows_impl(li);
        assert_eq!(v_rows.len(), li.get_capacity());
        v_rows
    }
    /// Real implementation to convert a logical input to virtual rows.
    fn logical_input_to_virtual_rows_impl(li: &Self::LogicalInput) -> Vec<Self::InputValue>;

    /// RLC virtual rows. A logical input might take multiple virtual rows.
    /// The default implementation is for the fixed length case.
    fn rlc_virtual_rows(
        (gate_ctx, rlc_ctx): (&mut Context<F>, &mut Context<F>),
        range_chip: &RangeChip<F>,
        rlc_chip: &RlcChip<F>,
        inputs: &[(Self::InputWitness, Self::OutputWitness)],
    ) -> Vec<AssignedValue<F>> {
        let input_multiplier = rlc_chip.rlc_pow_fixed(
            gate_ctx,
            &range_chip.gate,
            Self::OutputWitness::get_num_fields(),
        );

        inputs
            .iter()
            .map(|(input, output)| {
                let i_rlc = flatten_witness_to_rlc(rlc_ctx, rlc_chip, &input.clone().into());
                let o_rlc = flatten_witness_to_rlc(rlc_ctx, rlc_chip, &output.clone().into());
                range_chip.gate.mul_add(gate_ctx, i_rlc, input_multiplier, o_rlc)
            })
            .collect_vec()
    }
}

// ============= Data types passed between components =============
pub type TypelessLogicalInput = Vec<u8>;
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypelessPromiseCall {
    pub capacity: usize,
    pub logical_input: TypelessLogicalInput,
}

/// (Receiver ComponentType, serialized logical input)
pub type GroupedPromiseCalls = HashMap<ComponentTypeId, Vec<TypelessPromiseCall>>;
/// (typeless logical input, output)
pub type ComponentPromiseResult<F> = (TypelessLogicalInput, Vec<F>);

/// Metadata for a promise shard
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct PromiseShardMetadata<F: RawField> {
    pub commit: F,
    pub capacity: usize,
}
/// (shard index, shard data)
pub type SelectedDataShard<S> = (usize, S);
/// (shard index, vec of ComponentPromiseResult)
pub type SelectedPromiseResultShard<F> = SelectedDataShard<Vec<ComponentPromiseResult<F>>>;

#[derive(Debug, Clone, Getters, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct SelectedDataShardsInMerkle<F: RawField, S: Clone> {
    // metadata of leaves of this Merkle tree
    #[getset(get = "pub")]
    leaves: Vec<PromiseShardMetadata<F>>,
    /// Selected shards.
    #[getset(get = "pub")]
    shards: Vec<SelectedDataShard<S>>,
}

impl<F: Field, S: Clone> SelectedDataShardsInMerkle<F, S> {
    // create SelectedDataShardsInMerkle
    pub fn new(leaves: Vec<PromiseShardMetadata<F>>, shards: Vec<SelectedDataShard<S>>) -> Self {
        assert!(leaves.len().is_power_of_two());
        // TODO: check capacity of each shard.
        Self { leaves, shards }
    }
    /// Map data into another type.
    pub fn map_data<NS: Clone>(self, f: impl Fn(S) -> NS) -> SelectedDataShardsInMerkle<F, NS> {
        SelectedDataShardsInMerkle::new(
            self.leaves,
            self.shards.into_iter().map(|(i, s)| (i, f(s))).collect(),
        )
    }
}

/// Each shard is a virtual table, so shards is a vector of virtual tables.
pub type ComponentPromiseResultsInMerkle<F> =
    SelectedDataShardsInMerkle<F, Vec<ComponentPromiseResult<F>>>;

impl<F: Field> ComponentPromiseResultsInMerkle<F> {
    /// Helper function to create ComponentPromiseResults from a single shard.
    pub fn from_single_shard<T: ComponentType<F>>(lr: Vec<LogicalResult<F, T>>) -> Self {
        let vt = lr.iter().flat_map(T::logical_result_to_virtual_rows).collect_vec();
        let mut mock_builder = BaseCircuitBuilder::<F>::new(true).use_k(18).use_lookup_bits(8);
        let ctx = mock_builder.main(0);
        let witness_vt = vt
            .into_iter()
            .map(|(v_i, v_o)| (v_i.into().assign(ctx), v_o.into().assign(ctx)))
            .collect_vec();
        let witness_commit = T::Commiter::compute_commitment(&mut mock_builder, &witness_vt);
        let commit = *witness_commit.value();
        mock_builder.clear(); // prevent drop warning
        Self {
            leaves: vec![PromiseShardMetadata::<F> { commit, capacity: witness_vt.len() }],
            shards: vec![(0, lr.into_iter().map(|lr| lr.into()).collect())],
        }
    }
}
pub type GroupedPromiseResults<F> = HashMap<ComponentTypeId, ComponentPromiseResultsInMerkle<F>>;

assert_impl_all!(ComponentPromiseResultsInMerkle<Fr>: Serialize, DeserializeOwned);

pub const NUM_COMPONENT_OWNED_INSTANCES: usize = 2;

pub trait ComponentCircuit<F: Field> {
    fn clear_witnesses(&self);
    /// Compute promise calls.
    fn compute_promise_calls(&self) -> anyhow::Result<GroupedPromiseCalls>;
    /// Feed inputs into the core builder. The `input` type should be the `CoreInput` type specified by the `CoreBuilder`.
    /// It is the caller's responsibility to ensure that the capacity of the input
    /// is equal to the configured capacity of the component circuit. This function
    /// does **not** check this.
    fn feed_input(&self, input: Box<dyn Any>) -> anyhow::Result<()>;
    /// Fulfill promise results.
    fn fulfill_promise_results(
        &self,
        promise_results: &GroupedPromiseResults<F>,
    ) -> anyhow::Result<()>;
    /// When inputs and promise results are ready, we can generate outputs of this component.
    /// * When you call `compute_outputs`, `feed_inputs` must have already be called.
    /// * Input capacity checking should happen when calling `feed_inputs`, not in this function. This function assumes that the input capacity is equal to the configured capacity of the component circuit.
    // We don't have padding in the framework level because we don't have a formal interface to get a dummy input with capacity = 1. But even if we want to pad, it should happen when `feed_input`.
    /// * The only goal of `compute_outputs` is to return the virtual table and its commit.
    fn compute_outputs(&self) -> anyhow::Result<ComponentPromiseResultsInMerkle<F>>;
    // Get public instances of this component.
    fn get_public_instances(&self) -> ComponentPublicInstances<F>;
}

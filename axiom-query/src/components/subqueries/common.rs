use axiom_codec::types::field_elements::AnySubqueryResult;
use axiom_eth::{
    halo2_base::AssignedValue,
    utils::component::{
        types::{FixLenLogical, Flatten},
        utils::get_logical_value,
        ComponentPromiseResultsInMerkle, ComponentType, FlattenVirtualTable, LogicalResult,
    },
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::Field;

/// Generic type for output of a subquery shard circuit
#[derive(Clone, Default, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputSubqueryShard<I, O> {
    /// Vector is assumed to be resized to the capacity.
    pub results: Vec<AnySubqueryResult<I, O>>,
}

impl<I, O> OutputSubqueryShard<I, O> {
    pub fn len(&self) -> usize {
        self.results.len()
    }

    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    pub fn into_flattened_pairs<T>(self) -> Vec<(Flatten<T>, Flatten<T>)>
    where
        I: Into<Flatten<T>>,
        O: Into<Flatten<T>>,
        T: Copy,
    {
        self.results.into_iter().map(|r| (r.subquery.into(), r.value.into())).collect()
    }

    // cannot do blanket From implementation because it conflicts with Rust std T: From<T> impl
    pub fn convert_into<S, T>(self) -> OutputSubqueryShard<S, T>
    where
        I: Into<S>,
        O: Into<T>,
    {
        OutputSubqueryShard {
            results: self
                .results
                .into_iter()
                .map(|r| AnySubqueryResult { subquery: r.subquery.into(), value: r.value.into() })
                .collect(),
        }
    }
}

/// Helper function to convert OutputSubqueryShard into ComponentPromiseResults
pub fn shard_into_component_promise_results<F: Field, T: ComponentType<F>>(
    shard: OutputSubqueryShard<T::LogicalInput, T::OutputValue>,
) -> ComponentPromiseResultsInMerkle<F> {
    ComponentPromiseResultsInMerkle::from_single_shard(
        shard
            .results
            .into_iter()
            .map(|r| LogicalResult::<F, T>::new(r.subquery, r.value))
            .collect_vec(),
    )
}

pub(crate) fn extract_virtual_table<
    F: Field,
    S: Into<Flatten<AssignedValue<F>>>,
    T: Into<Flatten<AssignedValue<F>>>,
>(
    outputs: impl Iterator<Item = AnySubqueryResult<S, T>>,
) -> FlattenVirtualTable<AssignedValue<F>> {
    outputs.map(|output| (output.subquery.into(), output.value.into())).collect()
}

pub(crate) fn extract_logical_results<
    F: Field,
    S: FixLenLogical<AssignedValue<F>>,
    FS: FixLenLogical<F>,
    T: ComponentType<F, InputValue = FS, InputWitness = S, LogicalInput = FS>,
>(
    outputs: impl Iterator<Item = AnySubqueryResult<S, T::OutputWitness>>,
) -> Vec<LogicalResult<F, T>> {
    outputs
        .map(|output| {
            LogicalResult::<F, T>::new(
                get_logical_value(&output.subquery),
                get_logical_value(&output.value),
            )
        })
        .collect()
}

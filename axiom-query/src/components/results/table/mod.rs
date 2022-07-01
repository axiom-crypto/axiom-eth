use axiom_codec::types::field_elements::FlattenedSubqueryResult;
use axiom_eth::{
    halo2_base::{AssignedValue, Context},
    rlc::chip::RlcChip,
};
use serde::{Deserialize, Serialize};

use crate::{utils::codec::assign_flattened_subquery_result, Field};

pub(super) mod join;

/// The _ordered_ subqueries with results.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SubqueryResultsTable<T> {
    pub rows: Vec<FlattenedSubqueryResult<T>>,
}

impl<T> SubqueryResultsTable<T> {
    pub fn new(rows: Vec<FlattenedSubqueryResult<T>>) -> Self {
        Self { rows }
    }
}

pub type AssignedSubqueryResultsTable<F> = SubqueryResultsTable<AssignedValue<F>>;

impl<F: Field> SubqueryResultsTable<F> {
    /// Nothing is constrained. Loaded as pure private witnesses.
    pub fn assign(&self, ctx: &mut Context<F>) -> AssignedSubqueryResultsTable<F> {
        let rows: Vec<_> =
            self.rows.iter().map(|row| assign_flattened_subquery_result(ctx, row)).collect();
        SubqueryResultsTable { rows }
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

impl<F: Field> AssignedSubqueryResultsTable<F> {
    pub fn to_rlc(&self, ctx_rlc: &mut Context<F>, rlc: &RlcChip<F>) -> Vec<[AssignedValue<F>; 1]> {
        self.rows
            .iter()
            .map(|row| {
                let concat = row.to_fixed_array();
                let trace = rlc.compute_rlc_fixed_len(ctx_rlc, concat);
                [trace.rlc_val]
            })
            .collect()
    }
}

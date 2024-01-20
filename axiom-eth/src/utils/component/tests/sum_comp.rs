use crate::impl_flatten_conversion;
use halo2_base::{gates::GateInstructions, AssignedValue};
use itertools::Itertools;

use super::*;

// An example of variable length component.
// =============== Sum Component ===============

/// SumLogicalInput is the logical input of SumLogicalInput Component.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct SumLogicalInput {
    pub to_sum: Vec<u64>,
}

impl<F: Field> LogicalInputValue<F> for SumLogicalInput {
    fn get_capacity(&self) -> usize {
        if self.to_sum.is_empty() {
            1
        } else {
            self.to_sum.len()
        }
    }
}

const SUM_INPUT_FIELD_SIZE: [usize; 2] = [1, 64];

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FixLenLogicalInputSum<T: Clone> {
    pub is_final: T,
    pub to_add: T,
}
impl<T: Clone> TryFrom<Vec<T>> for FixLenLogicalInputSum<T> {
    type Error = anyhow::Error;
    fn try_from(mut value: Vec<T>) -> Result<Self, Self::Error> {
        if value.len() != 2 {
            return Err(anyhow::anyhow!("invalid length"));
        }
        let to_add = value.pop().unwrap();
        let is_final = value.pop().unwrap();

        Ok(FixLenLogicalInputSum::<T> { is_final, to_add })
    }
}

impl<T: Clone> FixLenLogicalInputSum<T> {
    pub fn flatten(self) -> Vec<T> {
        vec![self.is_final, self.to_add]
    }
}

impl_flatten_conversion!(FixLenLogicalInputSum, SUM_INPUT_FIELD_SIZE);

pub type FixLenLogicalOutputSum<T> = LogicalOutputAdd<T>;

#[derive(Debug, Clone)]
pub struct ComponentTypeSum<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> ComponentType<F> for ComponentTypeSum<F> {
    type InputValue = FixLenLogicalInputSum<F>;
    type InputWitness = FixLenLogicalInputSum<AssignedValue<F>>;
    type OutputValue = FixLenLogicalOutputSum<F>;
    type OutputWitness = FixLenLogicalOutputSum<AssignedValue<F>>;
    type LogicalInput = SumLogicalInput;

    fn get_type_id() -> ComponentTypeId {
        "axiom-eth:ComponentTypeSum".to_string()
    }

    fn logical_result_to_virtual_rows_impl(
        ins: &LogicalResult<F, Self>,
    ) -> Vec<(Self::InputValue, Self::OutputValue)> {
        let input = Self::logical_input_to_virtual_rows_impl(&ins.input);
        let mut to_sum = ins.input.to_sum.clone();
        if to_sum.is_empty() {
            to_sum.push(0);
        }
        let mut prefix_sum = Vec::with_capacity(to_sum.len());
        let mut curr = 0u128;
        for x in to_sum {
            curr += x as u128;
            prefix_sum.push(curr);
        }
        let output = prefix_sum
            .into_iter()
            .map(|ps| Self::OutputValue { c: F::from_u128(ps) })
            .collect_vec();
        input.into_iter().zip_eq(output).collect_vec()
    }
    fn logical_input_to_virtual_rows_impl(li: &Self::LogicalInput) -> Vec<Self::InputValue> {
        let len = li.to_sum.len();
        if len == 0 {
            vec![FixLenLogicalInputSum { is_final: F::ONE, to_add: F::ZERO }]
        } else {
            li.to_sum
                .iter()
                .enumerate()
                .map(|(idx, x)| FixLenLogicalInputSum {
                    is_final: if idx + 1 == len { F::ONE } else { F::ZERO },
                    to_add: F::from(*x),
                })
                .collect_vec()
        }
    }

    fn rlc_virtual_rows(
        (gate_ctx, _rlc_ctx): (&mut Context<F>, &mut Context<F>),
        range_chip: &RangeChip<F>,
        rlc_chip: &RlcChip<F>,
        inputs: &[(Self::InputWitness, Self::OutputWitness)],
    ) -> Vec<AssignedValue<F>> {
        // Overview:
        // 1. if is_final == 0, rlc = 0.
        // 2. if is_final == 1, rlc = rlc([input,result])
        // we don't need length information in RLC because zeros in the end will not affect the result.
        let gate = &range_chip.gate;

        let gamma = rlc_chip.rlc_pow_fixed(gate_ctx, gate, 1);
        let zero = gate_ctx.load_zero();

        let mut ret = Vec::with_capacity(inputs.len());
        let mut curr_rlc = zero;
        for (input, output) in inputs {
            curr_rlc = gate.mul_add(gate_ctx, curr_rlc, gamma, input.to_add);
            // rlc if is_final == 1
            let row_rlc = gate.mul_add(gate_ctx, curr_rlc, gamma, output.c);
            let to_push = gate.select(gate_ctx, row_rlc, zero, input.is_final);
            ret.push(to_push);
            curr_rlc = gate.select(gate_ctx, zero, curr_rlc, input.is_final);
        }
        ret
    }
}

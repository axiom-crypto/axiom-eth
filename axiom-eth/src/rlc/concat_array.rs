use std::iter;

use halo2_base::{
    gates::GateInstructions, utils::ScalarField, AssignedValue, Context, QuantumCell::Constant,
};

use super::{
    chip::RlcChip,
    circuit::builder::RlcContextPair,
    types::{AssignedVarLenVec, ConcatVarFixedArrayTrace, ConcatVarFixedArrayWitness},
};

/// Both `prefix` and `suffix` are fixed length arrays, with length known at compile time.
/// However `prefix` is used to represent a variable length array, with variable length given
/// by `prefix_len`.
///
/// This is the FirstPhase of computing `[&prefix[..prefix_len], &suffix[..]].concat()`.
/// This function **does not constrain anything**. It only computes the witness.
/// You **must** call [concat_var_fixed_array_phase1] to use RLC to constrain the concatenation.
pub fn concat_var_fixed_array_phase0<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    prefix: AssignedVarLenVec<F>,
    suffix: Vec<AssignedValue<F>>,
) -> ConcatVarFixedArrayWitness<F> {
    let concat_len = gate.add(ctx, prefix.len, Constant(F::from(suffix.len() as u64)));
    let max_concat_len = prefix.max_len() + suffix.len();
    let prefix_len = prefix.len.value().get_lower_64() as usize;
    assert!(prefix_len <= prefix.max_len());
    // Unsafe: unconstrained; to be constrained in phase1
    let concat_padded = ctx.assign_witnesses(
        prefix.values[..prefix_len]
            .iter()
            .chain(suffix.iter())
            .map(|a| *a.value())
            .chain(iter::repeat(F::ZERO))
            .take(max_concat_len),
    );
    let concat = AssignedVarLenVec { values: concat_padded, len: concat_len };

    ConcatVarFixedArrayWitness { prefix, suffix, concat }
}

pub fn concat_var_fixed_array_phase1<F: ScalarField>(
    (ctx_gate, ctx_rlc): RlcContextPair<F>,
    gate: &impl GateInstructions<F>,
    rlc: &RlcChip<F>,
    concat_witness: ConcatVarFixedArrayWitness<F>,
) -> ConcatVarFixedArrayTrace<F> {
    let ConcatVarFixedArrayWitness { prefix, suffix, concat } = concat_witness;
    let multiplier = rlc.rlc_pow_fixed(ctx_gate, gate, suffix.len());

    let prefix_rlc = rlc.compute_rlc((ctx_gate, ctx_rlc), gate, prefix.values, prefix.len);
    let suffix_rlc = rlc.compute_rlc_fixed_len(ctx_rlc, suffix);
    let concat_rlc = rlc.compute_rlc((ctx_gate, ctx_rlc), gate, concat.values, concat.len);

    let claimed_concat = gate.mul_add(ctx_gate, prefix_rlc.rlc_val, multiplier, suffix_rlc.rlc_val);
    ctx_gate.constrain_equal(&claimed_concat, &concat_rlc.rlc_val);

    ConcatVarFixedArrayTrace { prefix_rlc, suffix_rlc, concat_rlc }
}

//! Verify all block hashes in BlockResponse column against a given Merkle Mountain Range

use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::ScalarField,
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use itertools::Itertools;

use crate::{
    batch_query::hash::keccak_packed, keccak::KeccakChip, util::select_array_by_indicator, Field,
};

use super::FixedByteArray;

/// Input assumptions which must hold but which are not constrained in the circuit:
/// * `mmr` is Merkle Mountain Range in *increasing* order of peak size. Array of fixed length 32 byte arrays.
/// Array `mmr` is resized to a fixed max length.
/// * `mmr_list_len` is the length of the original list that `mmr` is a commitment to.
/// * `mmr_bits` is the same length as `mmr`. `mmr_bits[i]` is a bit that is 1 if `mmr[i]` is a non-empty peak, and 0 otherwise. In other words, `mmr_bits` is the little-endian bit representation of `mmr_list_len`.
#[allow(clippy::too_many_arguments)]
pub fn verify_mmr_proof<F: Field>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    keccak: &mut KeccakChip<F>,
    mmr: &[impl AsRef<[AssignedValue<F>]>],
    mmr_list_len: AssignedValue<F>,
    mmr_bits: &[AssignedValue<F>],
    list_id: AssignedValue<F>, // the index in underlying list
    leaf: FixedByteArray<F>,   // the leaf node at `list_id` in underlying list
    merkle_proof: Vec<FixedByteArray<F>>,
    not_empty: AssignedValue<F>, // actually do the proof check
) {
    assert!(!mmr.is_empty());
    let gate = range.gate();
    assert_eq!(mmr.len(), mmr_bits.len());
    let index_bits = range.gate().num_to_bits(ctx, list_id, mmr.len());
    range.check_less_than(ctx, list_id, mmr_list_len, mmr.len());
    // count how many leading (big-endian) bits `mmr_bits` and `index_bits` have in common
    let mut agree = Constant(F::one());
    let mut num_leading_agree = ctx.load_zero();
    for (a, b) in mmr_bits.iter().rev().zip(index_bits.iter().rev()) {
        let is_equal = bit_is_equal(ctx, gate, *a, *b);
        agree = Existing(gate.mul(ctx, agree, is_equal));
        num_leading_agree = gate.add(ctx, num_leading_agree, agree);
    }
    // if num_leading_agree = mmr.len() that means peak_id = mmr_list_len is outside of this MMR
    let max_peak_id = gate.get_field_element(mmr.len() as u64 - 1);
    let peak_id = gate.sub(ctx, Constant(max_peak_id), num_leading_agree);

    // we merkle prove `leaf` into `mmr[peak_id]` using `index_bits[..peak_id]` as the "side"
    assert_eq!(merkle_proof.len() + 1, mmr.len()); // max depth of a peak is mmr.len() - 1
    let mut intermediate_hashes = Vec::with_capacity(mmr.len());
    intermediate_hashes.push(leaf);
    // last index_bit is never used: if it were 1 then leading bit of mmr_bits would also have to be 1
    for (side, node) in index_bits.into_iter().zip(merkle_proof) {
        let cur = intermediate_hashes.last().unwrap();
        // Possible optimization: if merkle_proof consists of unassigned witnesses, they can be assigned while `select`ing here. We avoid this low-level optimization for code clarity for now.
        let concat = cur
            .0
            .iter()
            .chain(node.0.iter())
            .zip_eq(node.0.iter().chain(cur.0.iter()))
            .map(|(a, b)| gate.select(ctx, *b, *a, side))
            .collect_vec();
        let hash = keccak_packed(ctx, gate, keccak, FixedByteArray(concat));
        intermediate_hashes.push(hash);
    }
    let peak_indicator = gate.idx_to_indicator(ctx, peak_id, mmr.len());
    // get mmr[peak_id]
    debug_assert_eq!(mmr[0].as_ref().len(), 32);
    let peak = select_array_by_indicator(ctx, gate, mmr, &peak_indicator);
    let proof_peak = select_array_by_indicator(ctx, gate, &intermediate_hashes, &peak_indicator);
    for (a, b) in peak.into_iter().zip_eq(proof_peak) {
        let a = gate.mul(ctx, a, not_empty);
        let b = gate.mul(ctx, b, not_empty);
        ctx.constrain_equal(&a, &b);
    }
}

/// Assumes `a, b` are both bits.
///
/// Returns `a == b` as a bit.
pub fn bit_is_equal<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    a: AssignedValue<F>,
    b: AssignedValue<F>,
) -> AssignedValue<F> {
    // (a == b) = 1 - (a - b)^2
    let diff = gate.sub(ctx, a, b);
    // | 1 - (a-b)^2 | a-b | a-b | 1 |
    let out_val = F::one() - diff.value().square();
    ctx.assign_region([Witness(out_val), Existing(diff), Existing(diff), Constant(F::one())], [0]);
    ctx.get(-4)
}

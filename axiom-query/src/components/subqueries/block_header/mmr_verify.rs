use axiom_eth::{
    halo2_base::{
        gates::{GateInstructions, RangeChip, RangeInstructions},
        safe_types::{SafeBool, SafeBytes32, SafeTypeChip},
        utils::ScalarField,
        AssignedValue, Context,
        QuantumCell::{Constant, Existing},
    },
    keccak::{types::KeccakVarLenQuery, KeccakChip},
    utils::{is_zero_vec, load_h256_to_safe_bytes32},
};
use ethers_core::types::H256;
use itertools::Itertools;

use crate::Field;

use super::MMR_MAX_NUM_PEAKS;

/// `mmr` is Merkle Mountain Range in *increasing* order of peak size.
///
/// After construction it is guaranteed that:
/// * `mmr_num_blocks` is the length of the original list that `mmr` is a commitment to.
/// * `mmr_bits` is the same length as `mmr`. `mmr_bits[i]` is a bit that is 1 if `mmr[i]` is a non-empty peak, and 0 otherwise. In other words, `mmr_bits` is the little-endian bit representation of `mmr_num_blocks`.
#[derive(Clone, Debug)]
pub struct AssignedMmr<F: ScalarField> {
    pub mmr: [SafeBytes32<F>; MMR_MAX_NUM_PEAKS],
    pub mmr_bits: [SafeBool<F>; MMR_MAX_NUM_PEAKS],
    pub mmr_num_blocks: AssignedValue<F>,
}

pub fn assign_mmr<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    mmr: [H256; MMR_MAX_NUM_PEAKS],
) -> AssignedMmr<F> {
    let safe = SafeTypeChip::new(range);
    let gate = range.gate();
    let mmr = mmr.map(|peak| load_h256_to_safe_bytes32(ctx, &safe, peak));
    let mmr_bits = mmr
        .iter()
        .map(|peak| {
            let no_peak = is_zero_vec(ctx, gate, peak.value());
            SafeTypeChip::unsafe_to_bool(gate.not(ctx, no_peak))
        })
        .collect_vec();
    let mmr_num_blocks = gate.inner_product(
        ctx,
        mmr_bits.iter().map(|bit| *bit.as_ref()),
        gate.pow_of_two().iter().take(mmr_bits.len()).map(|x| Constant(*x)),
    );
    let mmr_bits = mmr_bits.try_into().unwrap();
    AssignedMmr { mmr, mmr_bits, mmr_num_blocks }
}

pub type AssignedMmrKeccak<F> = KeccakVarLenQuery<F>;

impl<F: Field> AssignedMmr<F> {
    pub fn keccak(
        &self,
        ctx: &mut Context<F>,
        keccak_chip: &KeccakChip<F>,
    ) -> AssignedMmrKeccak<F> {
        let gate = keccak_chip.gate();
        // mmr_num_peaks = bit_length(mmr_num_blocks) = MMR_MAX_NUM_PEAKS - num_leading_zeros(mmr_num_blocks)
        let mut is_leading = Constant(F::ONE);
        let mut num_leading_zeros = ctx.load_zero();
        for bit in self.mmr_bits.iter().rev() {
            // is_zero = 1 - bit
            // is_leading = is_leading * (is_zero)
            is_leading = Existing(gate.mul_not(ctx, *bit.as_ref(), is_leading));
            num_leading_zeros = gate.add(ctx, num_leading_zeros, is_leading);
        }
        let max_num_peaks = F::from(MMR_MAX_NUM_PEAKS as u64);
        let num_peaks = gate.sub(ctx, Constant(max_num_peaks), num_leading_zeros);
        let mmr_bytes = gate.mul(ctx, num_peaks, Constant(F::from(32u64)));
        keccak_chip.keccak_var_len(
            ctx,
            self.mmr.iter().flat_map(|bytes| bytes.value().iter().copied()).collect(),
            mmr_bytes,
            0,
        )
    }
}

/// `mmr` is a Merkle Mountan Range (MMR) of block hashes (bytes32).
/// It is a commitment to block hashes for blocks [0, mmr_num_blocks).
/// Given a `merkle_proof` of a block hash at index `list_id`,
/// we verify the merkle proof into the MMR.
///
/// If `not_empty` is None, then we definitely enforce the Merkle proof check.
/// If `not_empty` is Some, then we conditionally enforce the Merkle proof check
/// depending on the boolean flag.
pub fn verify_mmr_proof<F: Field>(
    ctx: &mut Context<F>,
    keccak: &KeccakChip<F>,
    assigned_mmr: &AssignedMmr<F>,
    list_id: AssignedValue<F>, // the index in underlying list
    leaf: SafeBytes32<F>,      // the leaf node at `list_id` in underlying list
    merkle_proof: Vec<SafeBytes32<F>>,
    not_empty: Option<SafeBool<F>>, // actually do the proof check
) {
    let AssignedMmr { mmr, mmr_bits, mmr_num_blocks } = assigned_mmr;
    assert!(!mmr.is_empty());
    let range = keccak.range();
    let gate = range.gate();
    assert_eq!(mmr.len(), mmr_bits.len());
    let index_bits = range.gate().num_to_bits(ctx, list_id, mmr.len());
    range.check_less_than(ctx, list_id, *mmr_num_blocks, mmr.len());
    // count how many leading (big-endian) bits `mmr_bits` and `index_bits` have in common
    let mut agree = Constant(F::ONE);
    let mut num_leading_agree = ctx.load_zero();
    for (a, b) in mmr_bits.iter().rev().zip(index_bits.iter().rev()) {
        let is_equal = bit_is_equal(ctx, gate, *a.as_ref(), *b);
        agree = Existing(gate.mul(ctx, agree, is_equal));
        num_leading_agree = gate.add(ctx, num_leading_agree, agree);
    }
    // if num_leading_agree = mmr.len() that means peak_id = mmr_list_len is outside of this MMR
    let max_peak_id = F::from(mmr.len() as u64 - 1);
    let peak_id = gate.sub(ctx, Constant(max_peak_id), num_leading_agree);

    // we merkle prove `leaf` into `mmr[peak_id]` using `index_bits[..peak_id]` as the "side"
    assert_eq!(merkle_proof.len() + 1, mmr.len()); // max depth of a peak is mmr.len() - 1
    let mut intermediate_hashes = Vec::with_capacity(mmr.len());
    intermediate_hashes.push(leaf);
    // last index_bit is never used: if it were 1 then leading bit of mmr_bits would also have to be 1
    for (side, node) in index_bits.into_iter().zip(merkle_proof) {
        let cur = intermediate_hashes.last().unwrap();
        // Possible optimization: if merkle_proof consists of unassigned witnesses, they can be assigned while `select`ing here. We avoid this low-level optimization for code clarity for now.
        let concat = (cur.value().iter().chain(node.value()))
            .zip_eq(node.value().iter().chain(cur.value()))
            .map(|(a, b)| gate.select(ctx, *b, *a, side))
            .collect_vec();
        let hash = keccak.keccak_fixed_len(ctx, concat).output_bytes;
        intermediate_hashes.push(hash);
    }
    let peak_indicator = gate.idx_to_indicator(ctx, peak_id, mmr.len());
    // get mmr[peak_id]
    debug_assert_eq!(mmr[0].as_ref().len(), 32);
    // H256 as bytes:
    let peak = gate.select_array_by_indicator(ctx, mmr, &peak_indicator);
    // H256 as bytes:
    let proof_peak = gate.select_array_by_indicator(ctx, &intermediate_hashes, &peak_indicator);
    // If Some, conditional selector on whether to check merkle proof validity
    let not_empty: Option<AssignedValue<F>> = not_empty.map(|x| x.into());
    for (mut a, mut b) in peak.into_iter().zip_eq(proof_peak) {
        if let Some(not_empty) = not_empty {
            a = gate.mul(ctx, a, not_empty);
            b = gate.mul(ctx, b, not_empty);
        }
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
    gate.sub_mul(ctx, Constant(F::ONE), diff, diff)
}

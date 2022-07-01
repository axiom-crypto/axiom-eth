use axiom_eth::{
    halo2_base::{
        gates::{GateInstructions, RangeChip, RangeInstructions},
        poseidon::hasher::PoseidonHasher,
        safe_types::SafeBool,
        utils::log2_ceil,
        AssignedValue, Context,
    },
    utils::circuit_utils::{log2_ceil as circuit_log2_ceil, unsafe_lt_mask},
};
use ethers_core::{types::H256, utils::keccak256};
use itertools::Itertools;

use crate::utils::codec::{get_num_fe_from_subquery_key, AssignedSubqueryResult};
use crate::Field;

/// The zip of `subquery_hashes` and `results` may be resized to some fixed length ordained
/// by the circuit. The true number of subqueries is given by `num_subqueries`, and we
/// want to compute the results root for those subqueries.
///
/// ## Definitions
/// - `subqueryResultsRoot`: The Keccak Merkle root of the padded tree (pad by bytes32(0)) with
/// even index leaves given by `subqueryHash := keccak(type . subqueryData)`
/// and odd index leaves given by the result `value` (all encoded in bytes).
/// -  `subqueryResultsPoseidonRoot`: see [get_results_root_poseidon].
///
/// Note: this is _almost_ the same as the Merkle root of the padded tree with leaves
/// given by `keccak(subqueryHash . value)`. The difference is that in the latter we must pad by
/// `keccak(bytes32(0) . bytes32(0))`.
///
/// ## Assumptions
/// - `num_subqueries <= results.len()`
/// - `subquery_hashes` and `results` are non-empty of the same length. This length is known
///   at compile time.
// Likely `results.len()` will already be a power of 2, so not worth optimizing anything there
pub fn get_results_root<F: Field, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    poseidon: &PoseidonHasher<F, T, RATE>,
    results: &[AssignedSubqueryResult<F>],
    num_subqueries: AssignedValue<F>,
) -> AssignedValue<F> {
    let gate = range.gate();
    let subquery_mask = unsafe_lt_mask(ctx, gate, num_subqueries, results.len());

    get_results_root_poseidon(ctx, range, poseidon, results, num_subqueries, &subquery_mask)
}

/// The subquery data and results vector `subquery_results` may be resized to some fixed length
/// ordained by the circuit. The true number of subqueries is given by `num_subqueries`, and we
/// want to compute the Poseidon results root for those subqueries.
///
/// ## Definition
/// `subqueryResultsPoseidonRoot`: The Poseidon Merkle root of the padded tree (pad by 0) with
/// leaves given by `poseidon(poseidon(type . fieldSubqueryData), value[..])`.
///
/// ### Note
/// `value` consists of multiple field elements, so the above means
/// `poseidon([[subqueryHashPoseidon], value[..]].concat())` with
/// `subqueryHashPoseidon := poseidon(type . fieldSubqueryData)` and `fieldSubqueryData` is
/// **variable length**.
/// The length of `fieldSubqueryData` is:
/// * the flattened length of the `FieldSubquery**` struct when the subquery type is not SolidityNestedMapping. This can be gotten as `NUM_FE_ANY[subquery_type]`.
/// * When the subquery type is SolidityNestedMapping, the length is `NUM_FE_SOLIDITY_NESTED_MAPPING_WITHOUT_KEYS + 2 * mapping_depth`. In other words, it's the flattened length of `FieldSubquerySolidityNestedMapping` where we resize based on the variable length of the keys.
///
/// ## Assumptions
/// - `subquery_results` is non-empty and its length is known at compile time.
/// - `num_subqueries <= results.len()`
/// - `subquery_mask[i] = i < num_subqueries ? 1 : 0`
/// - `subquery_hashes` and `results` are non-empty of the same length. This length is known
///   at compile time.
// Likely `results.len()` will already be a power of 2, so not worth optimizing anything there
pub fn get_results_root_poseidon<F: Field, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    initialized_hasher: &PoseidonHasher<F, T, RATE>,
    subquery_results: &[AssignedSubqueryResult<F>],
    num_subqueries: AssignedValue<F>,
    subquery_mask: &[SafeBool<F>],
) -> AssignedValue<F> {
    let gate = range.gate();

    let tree_depth = log2_ceil(subquery_results.len() as u64);
    let depth = circuit_log2_ceil(ctx, gate, num_subqueries, tree_depth + 1);
    // `depth_indicator = idx_to_indicator(log2ceil(num_subqueries), log2ceil(subquery_results.len()) + 1)`
    let depth_indicator = gate.idx_to_indicator(ctx, depth, tree_depth + 1);

    let const_zero = ctx.load_zero();

    let mut leaves = Vec::with_capacity(1 << tree_depth);
    for (subquery_result, &mask) in subquery_results.iter().zip_eq(subquery_mask) {
        let key = &subquery_result.key;
        let key_len = get_num_fe_from_subquery_key(ctx, gate, key);
        let subquery_hash = initialized_hasher.hash_var_len_array(ctx, range, &key.0, key_len);
        let concat = [&[subquery_hash], &subquery_result.value[..]].concat();
        let mut leaf = initialized_hasher.hash_fix_len_array(ctx, gate, &concat);
        leaf = gate.mul(ctx, leaf, mask);
        leaves.push(leaf);
    }
    leaves.resize(1 << tree_depth, const_zero);

    let mut layers = Vec::with_capacity(tree_depth + 1);
    layers.push(leaves);
    for i in 0..tree_depth {
        let prev_layer = &layers[i];
        let layer = (0..(prev_layer.len() + 1) / 2)
            .map(|j| {
                initialized_hasher.hash_fix_len_array(
                    ctx,
                    gate,
                    &[prev_layer[2 * j], prev_layer[2 * j + 1]],
                )
            })
            .collect();
        layers.push(layer);
    }

    // The correct root is layers[log2ceil(num_subqueries)][0]
    let root_candidates = layers.iter().map(|layer| layer[0]).collect_vec();
    gate.select_by_indicator(ctx, root_candidates, depth_indicator.to_vec())
}

// empty_root[idx] is the Merkle root of a tree of depth idx with bytes32(0)'s as leaves
fn generate_keccak_empty_roots(len: usize) -> Vec<H256> {
    let mut empty_roots = Vec::with_capacity(len);
    let mut root = H256::zero();
    empty_roots.push(root);
    for _ in 1..len {
        root = H256(keccak256([root.as_bytes(), root.as_bytes()].concat()));
        empty_roots.push(root);
    }
    empty_roots
}

lazy_static::lazy_static! {
    pub static ref KECCAK_EMPTY_ROOTS: Vec<H256> = generate_keccak_empty_roots(32);
}

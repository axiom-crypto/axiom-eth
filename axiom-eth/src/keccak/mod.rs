//! Firstly, the structs and functions in this module **DO NOT** constrain the computation of the keccak hash function.
//! Instead, they are meant to constrain the correctness of keccak hashes on a collection of variable length byte arrays
//! when given a commitment to a lookup table of keccak hashes from an external keccak "coprocessor" circuit.
//!
use core::iter::once;

use getset::Getters;
use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    safe_types::{SafeBytes32, SafeTypeChip},
    utils::{bit_length, ScalarField},
    AssignedValue, Context,
    QuantumCell::Constant,
};
use itertools::Itertools;
use zkevm_hashes::keccak::vanilla::param::NUM_BYTES_TO_SQUEEZE;

use crate::{
    keccak::promise::KeccakVarLenCall,
    utils::{
        bytes_be_to_u128, component::promise_collector::PromiseCaller, u128s_to_bytes_be,
        AssignedH256,
    },
    Field,
};

use self::{
    promise::KeccakFixLenCall,
    types::{ComponentTypeKeccak, KeccakFixedLenQuery, KeccakVarLenQuery},
};

mod component_shim;
/// Keccak Promise Loader
pub mod promise;
#[cfg(test)]
mod tests;
/// Types
pub mod types;

/// Thread-safe manager that collects all keccak queries and then constrains that the input, outputs
/// are correct with respect to an externally provided table of | encoding(input) | keccak(input) |.
#[derive(Clone, Debug, Getters)]
pub struct KeccakChip<F: Field> {
    #[getset(get = "pub")]
    promise_caller: PromiseCaller<F>,
    #[getset(get = "pub")]
    range: RangeChip<F>,
}

impl<F: Field> KeccakChip<F> {
    pub fn new(range: RangeChip<F>, promise_collector: PromiseCaller<F>) -> Self {
        Self::new_with_promise_collector(range, promise_collector)
    }
    pub fn new_with_promise_collector(
        range: RangeChip<F>,
        promise_collector: PromiseCaller<F>,
    ) -> Self {
        Self { range, promise_caller: promise_collector }
    }
    pub fn gate(&self) -> &GateChip<F> {
        &self.range.gate
    }

    /// Takes a byte vector of known fixed length and computes the keccak digest of `bytes`.
    /// - Returns `(output_bytes, output_hi, output_lo)`.
    /// - This function only computes witnesses for output bytes.
    ///
    /// # Assumptions
    /// - `input` elements have been range checked to be bytes
    /// - This assumption is rather **unsafe** and assumes the user is careful.
    // TODO: use SafeByte
    pub fn keccak_fixed_len(
        &self,
        ctx: &mut Context<F>,
        input: Vec<AssignedValue<F>>,
    ) -> KeccakFixedLenQuery<F> {
        let [output_hi, output_lo] = {
            let len = input.len();
            let output = self
                .promise_caller
                .call::<KeccakFixLenCall<F>, ComponentTypeKeccak<F>>(
                    ctx,
                    KeccakFixLenCall::new(SafeTypeChip::unsafe_to_fix_len_bytes_vec(
                        input.clone(),
                        len,
                    )),
                )
                .unwrap();
            output.hash.hi_lo()
        };

        // Decompose hi-lo into bytes (with range check). Right now we always provide the bytes for backwards compatibility.
        // In the future we may create them on demand.
        let output_bytes = u128s_to_bytes_be(ctx, self.range(), &[output_hi, output_lo]);
        // no good way to transmute from Vec<SafeByte> to SafeBytes32
        let output_raw: Vec<AssignedValue<_>> =
            output_bytes.into_iter().map(|b| b.into()).collect();
        let output_bytes = SafeTypeChip::unsafe_to_safe_type(output_raw);

        KeccakFixedLenQuery { input_assigned: input, output_bytes, output_hi, output_lo }
    }

    /// Takes a fixed length byte vector and computes the keccak digest of `bytes[..len]`.
    /// - Returns `(output_bytes, output_hi, output_lo)`.
    /// - This function only computes witnesses for output bytes.
    ///
    /// Constrains `min_len <= len <= bytes.len()`.
    ///
    /// # Assumptions
    /// - `input` elements have been range checked to be bytes
    /// - This assumption is rather **unsafe** and assumes the user is careful.
    // TODO: use SafeByte
    pub fn keccak_var_len(
        &self,
        ctx: &mut Context<F>,
        input: Vec<AssignedValue<F>>,
        len: AssignedValue<F>,
        min_len: usize,
    ) -> KeccakVarLenQuery<F> {
        let bytes = get_bytes(&input);
        let max_len = input.len();

        let range = self.range();
        range.check_less_than_safe(ctx, len, (max_len + 1) as u64);
        if min_len != 0 {
            range.check_less_than(
                ctx,
                Constant(F::from((min_len - 1) as u64)),
                len,
                bit_length((max_len + 1) as u64),
            );
        }
        let num_bytes = len.value().get_lower_64() as usize;
        debug_assert!(bytes.len() >= num_bytes);

        let [output_hi, output_lo] = {
            let output = self
                .promise_caller
                .call::<KeccakVarLenCall<F>, ComponentTypeKeccak<F>>(
                    ctx,
                    KeccakVarLenCall::new(
                        SafeTypeChip::unsafe_to_var_len_bytes_vec(input.clone(), len, max_len),
                        min_len,
                    ),
                )
                .unwrap();
            output.hash.hi_lo()
        };

        // Decompose hi-lo into bytes (with range check). Right now we always provide the bytes for backwards compatibility.
        // In the future we may create them on demand.
        let output_bytes = u128s_to_bytes_be(ctx, self.range(), &[output_hi, output_lo]);

        KeccakVarLenQuery {
            min_bytes: min_len,
            length: len,
            input_assigned: input,
            output_bytes: output_bytes.try_into().unwrap(),
            output_hi,
            output_lo,
        }
    }

    /// Computes the keccak merkle root of a tree with leaves `leaves`.
    ///
    /// Returns the merkle tree root as a byte array.
    ///
    /// # Assumptions
    /// - `leaves.len()` is a power of two.
    /// - Each element of `leaves` is a slice of assigned **byte** values.
    /// - The byte length of each element of `leaves` is known and fixed, i.e., we use `keccak_fixed_len` to perform the hashes.
    ///
    /// # Warning
    /// - This implementation currently has no domain separation between hashing leaves versus hashing inner nodes
    pub fn merkle_tree_root(
        &self,
        ctx: &mut Context<F>,
        leaves: &[impl AsRef<[AssignedValue<F>]>],
    ) -> (SafeBytes32<F>, AssignedH256<F>) {
        let depth = leaves.len().ilog2() as usize;
        debug_assert_eq!(1 << depth, leaves.len());
        assert_ne!(depth, 0, "Merkle root of a single leaf is ill-defined");

        // bottom layer hashes
        let mut hashes = leaves
            .chunks(2)
            .map(|pair| {
                let leaves_concat = [pair[0].as_ref(), pair[1].as_ref()].concat();
                self.keccak_fixed_len(ctx, leaves_concat)
            })
            .collect_vec();
        debug_assert_eq!(hashes.len(), 1 << (depth - 1));
        for d in (0..depth - 1).rev() {
            for i in 0..(1 << d) {
                let leaves_concat =
                    [2 * i, 2 * i + 1].map(|idx| hashes[idx].output_bytes.as_ref()).concat();
                hashes[i] = self.keccak_fixed_len(ctx, leaves_concat);
            }
        }
        (hashes[0].output_bytes.clone(), [hashes[0].output_hi, hashes[0].output_lo])
    }

    /// Computes a keccak merkle mountain range of a tree with leaves `leaves`.
    ///
    /// Assumptions:
    /// - Each element of `leaves` is a slice of assigned byte values of fixed length `NUM_BYTES_TO_SQUEEZE = 32`.
    /// - `num_leaves_bits` is the little endian bit representation of `num_leaves`
    /// - `leaves.len()` is a power of two (i.e., we have a full binary tree), but `leaves[num_leaves..]` can be arbitrary dummy leaves.
    /// - The byte length of each element of `leaves` is known and fixed, i.e., we use `keccak_fixed_len` to perform the hashes.
    ///
    /// Returns the merkle mountain range associated with `leaves[..num_leaves]`
    /// as a length `log_2(leaves.len()) + 1` vector of byte arrays.
    /// The mountain range is ordered with the largest mountain first. For example, if `num_leaves = leaves.len()` then the first mountain is the merkle root of the full tree.
    /// For `i` where `(num_leaves >> i) & 1 == 0`, the value of the corresponding peak should be considered UNDEFINED.
    ///
    /// The merkle root of the tree with leaves `leaves[..num_leaves]` can be recovered by successively hashing the elements in the merkle mountain range, in reverse order, corresponding to indices
    /// where `num_leaves` has a 1 bit.
    pub fn merkle_mountain_range(
        &self,
        ctx: &mut Context<F>,
        leaves: &[Vec<AssignedValue<F>>],
        num_leaves_bits: &[AssignedValue<F>],
    ) -> Vec<(SafeBytes32<F>, AssignedH256<F>)> {
        let max_depth = leaves.len().ilog2() as usize;
        assert_eq!(leaves.len(), 1 << max_depth);
        assert_eq!(num_leaves_bits.len(), max_depth + 1);

        // start_idx[i] = (num_leaves >> i) << i
        // below we will want to select `leaves[start_idx[depth+1]..start_idx[depth+1] + 2^depth] for depth = max_depth - 1, ..., 0
        // we do this with a barrel-shifter, by shifting `leaves` left by 2^i or 0 depending on the bit in `num_leaves_bits`
        // we skip the first shift by 2^max_depth because if num_leaves == 2^max_depth then all these subsequent peaks are undefined
        let mut shift_leaves = leaves.to_vec();
        once(self.merkle_tree_root(ctx, leaves))
            .chain(num_leaves_bits.iter().enumerate().rev().skip(1).map(|(depth, &sel)| {
                // no need to shift if we're at the end
                if depth != 0 {
                    let peak = self.merkle_tree_root(ctx, &shift_leaves[..(1usize << depth)]);
                    // shift left by sel == 1 ? 2^depth : 0
                    for i in 0..1 << depth {
                        debug_assert_eq!(shift_leaves[i].len(), NUM_BYTES_TO_SQUEEZE);
                        for j in 0..shift_leaves[i].len() {
                            shift_leaves[i][j] = self.gate().select(
                                ctx,
                                shift_leaves[i + (1 << depth)][j],
                                shift_leaves[i][j],
                                sel,
                            );
                        }
                    }
                    peak
                } else {
                    let leaf_bytes =
                        SafeTypeChip::unsafe_to_fix_len_bytes_vec(shift_leaves[0].clone(), 32)
                            .into_bytes();
                    let hi_lo: [_; 2] =
                        bytes_be_to_u128(ctx, self.gate(), &leaf_bytes).try_into().unwrap();
                    let bytes = SafeBytes32::try_from(leaf_bytes).unwrap();
                    (bytes, hi_lo)
                }
            }))
            .collect()
    }
}

// convert field values to u8:
pub fn get_bytes<F: ScalarField>(bytes: &[impl AsRef<AssignedValue<F>>]) -> Vec<u8> {
    // TODO: if we really wanted to optimize, we can pre-compute a HashMap<F, u8> containing just `F::from(byte as u64)` for each byte. I think the cost of hashing is still cheaper than performing the Montgomery reduction
    bytes.iter().map(|b| b.as_ref().value().get_lower_64() as u8).collect_vec()
}

//! PLACEHOLDER SHA-256 CHIP
use crate::Field;
use core::iter::once;
use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    utils::bit_length,
    AssignedValue, Context,
    QuantumCell::Constant,
};
use itertools::Itertools;
use sha2::{Digest, Sha256};

use crate::keccak::get_bytes;

pub(crate) const NUM_BYTES_TO_SQUEEZE: usize = 32;

#[derive(Clone, Debug)]
pub struct Sha256FixedLenQuery<F: Field> {
    pub input_bytes: Vec<u8>,
    pub input_assigned: Vec<AssignedValue<F>>,

    pub output_bytes: [u8; NUM_BYTES_TO_SQUEEZE],
    pub output_assigned: Vec<AssignedValue<F>>,
}

#[derive(Clone, Debug)]
pub struct Sha256VarLenQuery<F: Field> {
    pub min_bytes: usize,
    pub max_bytes: usize,
    pub num_bytes: usize,
    // if `length` is `None`, then this is a fixed length sha256 query
    // and it is assumed `min_bytes = max_bytes`
    pub length: AssignedValue<F>,
    pub input_bytes: Vec<u8>,
    pub input_assigned: Vec<AssignedValue<F>>,

    pub output_bytes: [u8; NUM_BYTES_TO_SQUEEZE],
    pub output_assigned: Vec<AssignedValue<F>>,
}

// TODO: this should be analogous to KeccakChip, but we should probably make a more general trait to reduce dup code
#[derive(Clone, Debug)]
pub struct Sha256Chip<'r, F: Field> {
    pub range: &'r RangeChip<F>,
}

pub fn sha256<T: AsRef<[u8]>>(bytes: T) -> [u8; NUM_BYTES_TO_SQUEEZE] {
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_ref());
    let output = hasher.finalize();
    output.into()
}

impl<'r, F: Field> Sha256Chip<'r, F> {
    pub fn new(range: &'r RangeChip<F>) -> Self {
        Self { range }
    }

    /// Takes a byte vector of known fixed length and computes the sha256 digest of `bytes`.
    /// - Returns `(output_assigned, output_bytes)`, where `output_bytes` is provided just for convenience.
    /// - This function only computes witnesses for output bytes.
    /// The guarantee is that in `SecondPhase`, `input_assigned` and `output_assigned`
    /// will have their RLCs computed and these RLCs will be constrained to equal the
    /// correct ones in the sha256 table.
    ///
    /// Assumes that `input_bytes` coincides with the values of `bytes_assigned` as bytes,
    /// if provided (`bytes` is used for faster witness generation).
    ///
    /// Returns the index in `self.fixed_len_queries` of the query.
    pub fn sha256_fixed_len(
        &self,
        ctx: &mut Context<F>,
        input_assigned: Vec<AssignedValue<F>>,
    ) -> Sha256FixedLenQuery<F> {
        let bytes = get_bytes(&input_assigned[..]);

        let output_bytes = sha256(&bytes);
        let output_assigned = ctx.assign_witnesses(output_bytes.iter().map(|b| F::from(*b as u64)));

        Sha256FixedLenQuery { input_bytes: bytes, input_assigned, output_bytes, output_assigned }
    }

    /// Takes a fixed length byte vector and computes the sha256 digest of `bytes[..len]`.
    /// - Returns `(output_assigned, output_bytes)`, where `output_bytes` is provided just for convenience.
    /// - This function only computes witnesses for output bytes.
    /// The guarantee is that in `SecondPhase`, `input_assigned` and `output_assigned`
    /// will have their RLCs computed and these RLCs will be constrained to equal the
    /// correct ones in the sha256 table.
    ///
    /// Assumes that `input_bytes[..len]` coincides with the values of `input_assigned[..len]` as bytes, if provided (`bytes` is used for faster witness generation).
    ///
    /// Constrains `min_len <= len <= bytes.len()`.
    ///
    /// Returns the index in `self.var_len_queries` of the query.
    pub fn sha256_var_len(
        &self,
        ctx: &mut Context<F>,
        input_assigned: Vec<AssignedValue<F>>,
        len: AssignedValue<F>,
        min_len: usize,
    ) -> Sha256VarLenQuery<F> {
        let bytes = get_bytes(&input_assigned[..]);
        let max_len = input_assigned.len();

        let range = &self.range;
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
        let output_bytes = sha256(&bytes[..num_bytes]);
        let output_assigned = ctx.assign_witnesses(output_bytes.iter().map(|b| F::from(*b as u64)));

        Sha256VarLenQuery {
            min_bytes: min_len,
            max_bytes: max_len,
            num_bytes,
            length: len,
            input_bytes: bytes,
            input_assigned,
            output_bytes,
            output_assigned,
        }
    }

    /// Computes the sha256 merkle root of a tree with leaves `leaves`.
    ///
    /// Returns the merkle tree root as a byte array.
    ///
    /// # Assumptions
    /// - `leaves.len()` is a power of two.
    /// - Each element of `leaves` is a slice of assigned byte values.
    /// - The byte length of each element of `leaves` is known and fixed, i.e., we use `sha256_fixed_len` to perform the hashes.
    ///
    /// # Warning
    /// - This implementation currently has no domain separation between hashing leaves versus hashing inner nodes
    pub fn merkle_tree_root(
        &mut self,
        ctx: &mut Context<F>,
        leaves: &[impl AsRef<[AssignedValue<F>]>],
    ) -> Vec<AssignedValue<F>> {
        let depth = leaves.len().ilog2() as usize;
        debug_assert_eq!(1 << depth, leaves.len());
        if depth == 0 {
            return leaves[0].as_ref().to_vec();
        }

        // bottom layer hashes
        let mut hashes = leaves
            .chunks(2)
            .map(|pair| {
                let leaves_concat = [pair[0].as_ref(), pair[1].as_ref()].concat();
                self.sha256_fixed_len(ctx, leaves_concat)
            })
            .collect_vec();
        debug_assert_eq!(hashes.len(), 1 << (depth - 1));
        for d in (0..depth - 1).rev() {
            for i in 0..(1 << d) {
                let leaves_concat =
                    [2 * i, 2 * i + 1].map(|idx| &hashes[idx].output_assigned[..]).concat();
                hashes[i] = self.sha256_fixed_len(ctx, leaves_concat);
            }
        }
        hashes[0].output_assigned.clone()
    }

    /// Computes a sha256 merkle mountain range of a tree with leaves `leaves`.
    ///
    /// Assumptions:
    /// - Each element of `leaves` is a slice of assigned byte values of fixed length `NUM_BYTES_TO_SQUEEZE = 32`.
    /// - `num_leaves_bits` is the little endian bit representation of `num_leaves`
    /// - `leaves.len()` is a power of two (i.e., we have a full binary tree), but `leaves[num_leaves..]` can be arbitrary dummy leaves.
    /// - The byte length of each element of `leaves` is known and fixed, i.e., we use `sha256_fixed_len` to perform the hashes.
    ///
    /// Returns the merkle mountain range associated with `leaves[..num_leaves]`
    /// as a length `log_2(leaves.len()) + 1` vector of byte arrays.
    /// The mountain range is ordered with the largest mountain first. For example, if `num_leaves = leaves.len()` then the first mountain is the merkle root of the full tree.
    /// For `i` where `(num_leaves >> i) & 1 == 0`, the value of the corresponding peak should be considered UNDEFINED.
    ///
    /// The merkle root of the tree with leaves `leaves[..num_leaves]` can be recovered by successively hashing the elements in the merkle mountain range, in reverse order, corresponding to indices
    /// where `num_leaves` has a 1 bit.
    pub fn merkle_mountain_range(
        &mut self,
        ctx: &mut Context<F>,
        leaves: &[Vec<AssignedValue<F>>],
        num_leaves_bits: &[AssignedValue<F>],
    ) -> Vec<Vec<AssignedValue<F>>> {
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
                let peak = self.merkle_tree_root(ctx, &shift_leaves[..(1usize << depth)]);
                // no need to shift if we're at the end
                if depth != 0 {
                    // shift left by sel == 1 ? 2^depth : 0
                    for i in 0..1 << depth {
                        debug_assert_eq!(shift_leaves[i].len(), NUM_BYTES_TO_SQUEEZE);
                        for j in 0..shift_leaves[i].len() {
                            shift_leaves[i][j] = self.range.gate.select(
                                ctx,
                                shift_leaves[i + (1 << depth)][j],
                                shift_leaves[i][j],
                                sel,
                            );
                        }
                    }
                }

                peak
            }))
            .collect()
    }
}

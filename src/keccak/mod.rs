use crate::{
    halo2_proofs::circuit::Region,
    rlp::rlc::{RlcChip, RlcFixedTrace, RlcTrace},
};
use core::iter::once;
use ethers_core::utils::keccak256;
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    halo2_proofs::circuit::Value,
    utils::{bit_length, value_to_option, ScalarField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use itertools::Itertools;
use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
pub(crate) use zkevm_keccak::KeccakConfig;
use zkevm_keccak::{
    keccak_packed_multi::{
        get_num_keccak_f, get_num_rows_per_round, keccak_phase0, multi_keccak_phase1, KeccakRow,
    },
    util::{eth_types::Field, NUM_BYTES_TO_SQUEEZE, NUM_ROUNDS, NUM_WORDS_TO_SQUEEZE, RATE},
};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct KeccakFixedLenQuery<'v, F: Field> {
    pub input_bytes: Vec<u8>,
    pub input_assigned: Vec<AssignedValue<'v, F>>,

    pub output_bytes: [u8; NUM_BYTES_TO_SQUEEZE],
    pub output_assigned: Vec<AssignedValue<'v, F>>,
}

#[derive(Clone, Debug)]
pub struct KeccakVarLenQuery<'v, F: Field> {
    pub min_bytes: usize,
    pub max_bytes: usize,
    pub num_bytes: usize,
    // if `length` is `None`, then this is a fixed length keccak query
    // and it is assumed `min_bytes = max_bytes`
    pub length: AssignedValue<'v, F>,
    pub input_bytes: Vec<u8>,
    pub input_assigned: Vec<AssignedValue<'v, F>>,

    pub output_bytes: [u8; NUM_BYTES_TO_SQUEEZE],
    pub output_assigned: Vec<AssignedValue<'v, F>>,
}

#[derive(Clone, Debug)]
pub struct KeccakChip<'v, F: Field> {
    pub config: KeccakConfig<F>,
    num_rows_per_round: usize,
    pub var_len_queries: Vec<KeccakVarLenQuery<'v, F>>,
    pub fixed_len_queries: Vec<KeccakFixedLenQuery<'v, F>>,
    squeeze_digests: Vec<[F; NUM_WORDS_TO_SQUEEZE]>,
}

impl<'v, F: Field> KeccakChip<'v, F> {
    pub fn new(config: KeccakConfig<F>) -> Self {
        let num_rows_per_round = get_num_rows_per_round();
        Self {
            config,
            num_rows_per_round,
            var_len_queries: vec![],
            fixed_len_queries: vec![],
            squeeze_digests: vec![],
        }
    }

    /// Takes a byte vector of known fixed length and computes the keccak digest of `bytes`.
    /// - Returns `(output_assigned, output_bytes)`, where `output_bytes` is provided just for convenience.
    /// - This function only computes witnesses for output bytes.
    /// The guarantee is that in `SecondPhase`, `input_assigned` and `output_assigned`
    /// will have their RLCs computed and these RLCs will be constrained to equal the
    /// correct ones in the keccak table.
    ///
    /// Assumes that `input_bytes` coincides with the values of `bytes_assigned` as bytes,
    /// if provided (`bytes` is used for faster witness generation).
    pub fn keccak_fixed_len(
        &mut self,
        ctx: &mut Context<'_, F>,
        gate: &impl GateInstructions<F>,
        input_assigned: Vec<AssignedValue<'v, F>>,
        input_bytes: Option<Vec<u8>>,
    ) -> usize {
        let bytes = input_bytes.unwrap_or_else(|| get_bytes(&input_assigned[..]));
        debug_assert_eq!(bytes.len(), input_assigned.len());

        let output_bytes = keccak256(&bytes);
        let output_assigned = gate.assign_witnesses(
            ctx,
            output_bytes.iter().map(|b| Value::known(gate.get_field_element(*b as u64))),
        );

        self.fixed_len_queries.push(KeccakFixedLenQuery {
            input_bytes: bytes,
            input_assigned,
            output_bytes,
            output_assigned,
        });
        self.fixed_len_queries.len() - 1
    }

    /// Takes a fixed length byte vector and computes the keccak digest of `bytes[..len]`.
    /// - Returns `(output_assigned, output_bytes)`, where `output_bytes` is provided just for convenience.
    /// - This function only computes witnesses for output bytes.
    /// The guarantee is that in `SecondPhase`, `input_assigned` and `output_assigned`
    /// will have their RLCs computed and these RLCs will be constrained to equal the
    /// correct ones in the keccak table.
    ///
    /// Assumes that `input_bytes[..len]` coincides with the values of `input_assigned[..len]` as bytes, if provided (`bytes` is used for faster witness generation).
    ///
    /// Constrains `min_len <= len <= bytes.len()`.
    ///
    /// Returns output in bytes.
    pub fn keccak_var_len(
        &mut self,
        ctx: &mut Context<'v, F>,
        range: &impl RangeInstructions<F>,
        input_assigned: Vec<AssignedValue<'v, F>>,
        input_bytes: Option<Vec<u8>>,
        len: AssignedValue<'v, F>,
        min_len: usize,
    ) -> usize {
        let bytes = input_bytes.unwrap_or_else(|| get_bytes(&input_assigned[..]));
        let max_len = input_assigned.len();

        range.check_less_than_safe(ctx, &len, (max_len + 1) as u64);
        if min_len != 0 {
            range.check_less_than(
                ctx,
                Constant(range.gate().get_field_element((min_len - 1) as u64)),
                Existing(&len),
                bit_length((max_len + 1) as u64),
            );
        }
        let num_bytes =
            value_to_option(len.value()).map(|v| v.get_lower_32() as usize).unwrap_or(min_len);
        debug_assert!(bytes.len() >= num_bytes);
        let output_bytes = keccak256(&bytes[..num_bytes]);
        let output_assigned = range.gate().assign_witnesses(
            ctx,
            output_bytes.iter().map(|b| Value::known(range.gate().get_field_element(*b as u64))),
        );

        self.var_len_queries.push(KeccakVarLenQuery {
            min_bytes: min_len,
            max_bytes: max_len,
            num_bytes,
            length: len,
            input_bytes: bytes,
            input_assigned,
            output_bytes,
            output_assigned,
        });
        self.var_len_queries.len() - 1
    }

    /// Computes the keccak merkle root of a tree with leaves `leaves`.
    ///
    /// Assumptions:
    /// - `leaves.len()` is a power of two.
    /// - Each element of `leaves` is a slice of assigned byte values.
    /// - The byte length of each element of `leaves` is known and fixed, i.e., we use `keccak_fixed_len` to perform the hashes.
    ///
    /// Returns the merkle tree root as a byte array.
    pub fn merkle_tree_root(
        &mut self,
        ctx: &mut Context<'_, F>,
        gate: &impl GateInstructions<F>,
        leaves: &[Vec<AssignedValue<'v, F>>],
    ) -> Vec<AssignedValue<'v, F>> {
        let depth = leaves.len().ilog2() as usize;
        debug_assert_eq!(1 << depth, leaves.len());
        if depth == 0 {
            return leaves[0].to_vec();
        }

        // bottom layer hashes
        let mut hashes = leaves
            .chunks(2)
            .into_iter()
            .map(|pair| {
                let leaves_concat = [&pair[0][..], &pair[1][..]].concat();
                self.keccak_fixed_len(ctx, gate, leaves_concat, None)
            })
            .collect_vec();
        debug_assert_eq!(hashes.len(), 1 << (depth - 1));
        for d in (0..depth - 1).rev() {
            for i in 0..(1 << d) {
                let bytes_concat = [2 * i, 2 * i + 1]
                    .map(|idx| &self.fixed_len_queries[hashes[idx]].output_bytes[..])
                    .concat();
                let leaves_concat = [2 * i, 2 * i + 1]
                    .map(|idx| &self.fixed_len_queries[hashes[idx]].output_assigned[..])
                    .concat();
                hashes[i] = self.keccak_fixed_len(ctx, gate, leaves_concat, Some(bytes_concat));
            }
        }
        self.fixed_len_queries[hashes[0]].output_assigned.clone()
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
    /// as a length `log_2(leaves.len()) + 1` vector of byte arrays. The mountain range is ordered with the largest mountain first. For example, if `num_leaves = leaves.len()` then the first mountain is the merkle root of the full tree.
    ///
    /// The merkle root of the tree with leaves `leaves[..num_leaves]` can be recovered by successively hashing the elements in the merkle mountain range, in reverse order, corresponding to indices
    /// where `num_leaves` has a 1 bit.
    pub fn merkle_mountain_range(
        &mut self,
        ctx: &mut Context<'_, F>,
        gate: &impl GateInstructions<F>,
        leaves: &[Vec<AssignedValue<'v, F>>],
        num_leaves_bits: &[AssignedValue<'v, F>],
    ) -> Vec<Vec<AssignedValue<'v, F>>> {
        let max_depth = leaves.len().ilog2() as usize;
        assert_eq!(leaves.len(), 1 << max_depth);
        debug_assert_eq!(num_leaves_bits.len(), max_depth + 1);

        let mountain_range_start_positions = {
            // we start at 0 and go through bits of `num_leaves` in big endian order
            // if `(num_leaves >> i) & 1` then we add 2^i
            // Note that if num_leaves = 2^max_depth, then these all equal 2^max_depth
            gate.inner_product_with_sums(
                ctx,
                num_leaves_bits[..=max_depth].iter().rev().map(Existing),
                gate.pow_of_two()[..=max_depth].iter().rev().cloned().map(Constant),
            )
        };

        once(self.merkle_tree_root(ctx, gate, leaves))
            .chain(mountain_range_start_positions.zip((0..max_depth).rev()).map(
                |(start_idx, depth)| {
                    // generate the sub-leaves `leaves[start_idx..start_idx + 2^depth]`
                    let subleaves = (0..(1 << depth))
                        .map(|idx| {
                            let leaf_idx = gate.add(
                                ctx,
                                Existing(&start_idx),
                                Constant(gate.get_field_element(idx)),
                            );
                            (0..NUM_BYTES_TO_SQUEEZE)
                                .map(|byte_idx| {
                                    gate.select_from_idx(
                                        ctx,
                                        leaves.iter().map(|leaf| Existing(&leaf[byte_idx])),
                                        Existing(&leaf_idx),
                                    )
                                })
                                .collect_vec()
                        })
                        .collect_vec();

                    self.merkle_tree_root(ctx, gate, &subleaves)
                },
            ))
            .collect()
    }

    /// Do this at the end of `FirstPhase` and then call `assign_phase1` in `SecondPhase`.
    pub fn assign_phase0(&mut self, region: &mut Region<'_, F>) {
        let capacity: usize = self
            .fixed_len_queries
            .iter()
            .map(|q| q.input_assigned.len())
            .chain(self.var_len_queries.iter().map(|q| q.max_bytes))
            .map(get_num_keccak_f)
            .sum();
        let unused_capacity: usize = self
            .var_len_queries
            .iter()
            .map(|q| get_num_keccak_f(q.max_bytes) - get_num_keccak_f(q.num_bytes))
            .sum();

        let mut squeeze_digests = Vec::with_capacity(capacity);
        let mut num_rows_used = 0;

        // Dummy first rows so that the initial data is absorbed
        // The initial data doesn't really matter, `is_final` just needs to be disabled.
        for (idx, row) in KeccakRow::dummy_rows(self.num_rows_per_round).iter().enumerate() {
            self.config.set_row(region, idx, row);
        }
        num_rows_used += self.num_rows_per_round;

        // Generate witnesses for the fixed length queries first since there's no issue of selection
        let artifacts_fixed = self
            .fixed_len_queries
            .par_iter()
            .map(|query| {
                let num_keccak_f = get_num_keccak_f(query.input_bytes.len());
                let mut squeeze_digests = Vec::with_capacity(num_keccak_f);
                let mut rows =
                    Vec::with_capacity(num_keccak_f * (NUM_ROUNDS + 1) * self.num_rows_per_round);
                keccak_phase0(&mut rows, &mut squeeze_digests, &query.input_bytes);
                (rows, squeeze_digests)
            })
            .collect::<Vec<_>>();
        // Generate witnesses for the variable length queries
        let artifacts_var = self
            .var_len_queries
            .par_iter()
            .map(|query| {
                let num_keccak_f = get_num_keccak_f(query.num_bytes);
                let mut squeeze_digests = Vec::with_capacity(num_keccak_f);
                let mut rows =
                    Vec::with_capacity(num_keccak_f * (NUM_ROUNDS + 1) * self.num_rows_per_round);
                keccak_phase0(
                    &mut rows,
                    &mut squeeze_digests,
                    &query.input_bytes[..query.num_bytes],
                );
                (rows, squeeze_digests)
            })
            .collect::<Vec<_>>();
        // Generate extra witnesses to fill up keccak table up to `capacity`
        let artifacts_extra = (0..unused_capacity)
            .into_par_iter()
            .map(|_| {
                let mut squeeze_digests = Vec::with_capacity(1);
                let mut rows = Vec::with_capacity((NUM_ROUNDS + 1) * self.num_rows_per_round);
                keccak_phase0(&mut rows, &mut squeeze_digests, &[]);
                (rows, squeeze_digests)
            })
            .collect::<Vec<_>>();

        for (rows, squeezes) in artifacts_fixed
            .into_iter()
            .chain(artifacts_var.into_iter())
            .chain(artifacts_extra.into_iter())
        {
            for row in rows {
                self.config.set_row(region, num_rows_used, &row);
                num_rows_used += 1;
            }
            squeeze_digests.extend(squeezes);
        }
        self.squeeze_digests = squeeze_digests;
    }

    // pass in RLCs in case they are computed elsewhere in a different chip
    /// Assume `fixed_len_rlcs.len() = self.fixed_len_queries.len()` and
    /// `var_len_rlcs.len() = self.var_len_queries.len()`.
    pub fn assign_phase1(
        &mut self,
        ctx: &mut Context<'v, F>,
        range: &impl RangeInstructions<F>,
        challenge: Value<F>,
        fixed_len_rlcs: &[(RlcFixedTrace<'v, F>, RlcFixedTrace<'v, F>)],
        var_len_rlcs: &[(RlcTrace<'v, F>, RlcFixedTrace<'v, F>)],
    ) {
        let gate = range.gate();
        let keccak_table = &self.config.keccak_table;
        // the input and output rlcs in the keccak table
        let (input_rlcs, output_rlcs) = multi_keccak_phase1(
            &mut ctx.region,
            keccak_table,
            self.fixed_len_queries
                .iter()
                .map(|q| &q.input_bytes[..])
                .chain(self.var_len_queries.iter().map(|q| &q.input_bytes[..q.num_bytes])),
            challenge,
            self.squeeze_digests.drain(..).collect(),
        );

        let mut min_keccak_f = 0;
        let mut max_keccak_f = 0;
        for (input_rlc, output_rlc) in fixed_len_rlcs.iter() {
            min_keccak_f += get_num_keccak_f(input_rlc.len);
            max_keccak_f += get_num_keccak_f(input_rlc.len);

            ctx.constrain_equal(&input_rlcs[min_keccak_f - 1], &input_rlc.rlc_val);
            ctx.constrain_equal(&output_rlcs[min_keccak_f - 1], &output_rlc.rlc_val);
        }
        let mut running_num_squeezed =
            gate.load_constant(ctx, gate.get_field_element(min_keccak_f as u64));

        assert_eq!(self.var_len_queries.len(), var_len_rlcs.len());
        for (query, (input_rlc, output_rlc)) in self.var_len_queries.iter().zip(var_len_rlcs.iter())
        {
            min_keccak_f += get_num_keccak_f(query.min_bytes);
            max_keccak_f += get_num_keccak_f(query.max_bytes);

            let (table_input_rlc, table_output_rlc) = if min_keccak_f == max_keccak_f {
                running_num_squeezed =
                    gate.load_constant(ctx, gate.get_field_element(min_keccak_f as u64));
                (input_rlcs[min_keccak_f - 1].clone(), output_rlcs[min_keccak_f - 1].clone())
            } else {
                // num_keccak_f = length / RATE + 1
                let cap_floor = div_floor(ctx, range, &query.length, RATE as u32);
                let num_keccak_f = gate.add(ctx, Existing(&cap_floor), Constant(F::one()));
                running_num_squeezed =
                    gate.add(ctx, Existing(&running_num_squeezed), Existing(&num_keccak_f));
                // we want to select running_num_squeezed from min_keccak_f..=max_keccak_f
                let keccak_idx = gate.sub(
                    ctx,
                    Existing(&running_num_squeezed),
                    Constant(gate.get_field_element(min_keccak_f as u64)),
                );
                let input_rlc = gate.select_from_idx(
                    ctx,
                    input_rlcs[min_keccak_f - 1..max_keccak_f].iter().map(Existing),
                    Existing(&keccak_idx),
                );
                let output_rlc = gate.select_from_idx(
                    ctx,
                    output_rlcs[min_keccak_f - 1..max_keccak_f].iter().map(Existing),
                    Existing(&keccak_idx),
                );
                (input_rlc, output_rlc)
            };
            ctx.constrain_equal(&input_rlc.rlc_val, &table_input_rlc);
            ctx.constrain_equal(&output_rlc.rlc_val, &table_output_rlc);
        }
        self.fixed_len_queries.clear();
        self.var_len_queries.clear();
        #[cfg(feature = "display")]
        Self::print_stats(ctx, input_rlcs.len());
    }

    pub fn compute_all_rlcs(
        &mut self,
        ctx: &mut Context<'v, F>,
        rlc: &mut RlcChip<'v, F>,
        gate: &impl GateInstructions<F>,
    ) -> (
        Vec<(RlcFixedTrace<'v, F>, RlcFixedTrace<'v, F>)>,
        Vec<(RlcTrace<'v, F>, RlcFixedTrace<'v, F>)>,
    ) {
        // TODO: not very efficient, using drain to remove vectors without moving `self`
        let fixed_len_rlcs = self
            .fixed_len_queries
            .iter_mut()
            .map(|q| {
                let input_rlc =
                    rlc.compute_rlc_fixed_len(ctx, gate, q.input_assigned.drain(..).collect());
                let output_rlc =
                    rlc.compute_rlc_fixed_len(ctx, gate, q.output_assigned.drain(..).collect());
                (input_rlc, output_rlc)
            })
            .collect::<Vec<_>>();

        let var_len_rlcs = self
            .var_len_queries
            .iter_mut()
            .map(|q| {
                let input_rlc = rlc.compute_rlc(
                    ctx,
                    gate,
                    q.input_assigned.drain(..).collect(),
                    q.length.clone(),
                );
                let output_rlc =
                    rlc.compute_rlc_fixed_len(ctx, gate, q.output_assigned.drain(..).collect());
                (input_rlc, output_rlc)
            })
            .collect::<Vec<_>>();
        (fixed_len_rlcs, var_len_rlcs)
    }

    #[cfg(feature = "display")]
    pub fn print_stats(ctx: &Context<F>, num_keccak_f: usize) {
        use zkevm_keccak::util::NUM_WORDS_TO_ABSORB;

        println!("Number of keccak_f permutations: {num_keccak_f}");
        let rows_per_round =
            ctx.max_rows / (num_keccak_f * (NUM_ROUNDS + 1) + 1 + NUM_WORDS_TO_ABSORB);
        println!("Optimal keccak rows per round: {rows_per_round}");
    }
}

// convert field values to u8:
pub fn get_bytes<F: ScalarField>(bytes_assigned: &[AssignedValue<F>]) -> Vec<u8> {
    bytes_assigned
        .iter()
        .map(|abyte| value_to_option(abyte.value().map(|v| v.get_lower_32() as u8)).unwrap_or(0))
        .collect_vec()
}

pub fn div_floor<'v, F: ScalarField>(
    ctx: &mut Context<'v, F>,
    range: &impl RangeInstructions<F>,
    len: &AssignedValue<'v, F>,
    rate: u32,
) -> AssignedValue<'v, F> {
    let mut val = 0;
    len.value().map(|v| val = v.get_lower_32());
    let (div, rem) = (val / rate, val % rate);
    let [rate_f, div, rem] = [rate, div, rem].map(|v| range.gate().get_field_element(v as u64));
    let assigned = range.gate().assign_region(
        ctx,
        vec![
            Witness(Value::known(rem)),
            Constant(rate_f),
            Witness(Value::known(div)),
            Existing(len),
        ],
        vec![(0, None)],
    );
    range.check_less_than_safe(ctx, &assigned[0], rate as u64);
    assigned[2].clone()
}

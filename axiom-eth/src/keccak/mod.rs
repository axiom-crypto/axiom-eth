//! This module integrates the zkEVM keccak circuit with Axiom's circuits and API.
//!
//! Recall that the way zkEVM keccak works is that it proceeds in iterations of keccak_f,
//! squeezing out a new value per keccak_f.
//! Selectors are used to tell it in which rounds to absorb new bytes. For each call of keccak on some input bytes,
//! the circuit pads the bytes and adds the results squeezed out after each keccak_f in the process of computing the keccak
//! of the padded input.
//!
//! In Axiom's circuits, we will queue up all Keccaks that need to be computed throughout, with some extra logic to
//! handle variable length inputs. Then we
//! * compute all keccaks at once in zkevm-keccak sub-circuit
//! * calculate the RLCs of the input bytes and the output bytes in our own sub-circuit
//! * constrain the RLCs are equal
use crate::{
    halo2_proofs::circuit::Region,
    rlp::{
        builder::{
            assign_prover_phase0, assign_prover_phase1, KeygenAssignments, RlcThreadBreakPoints,
            RlcThreadBuilder,
        },
        rlc::{RlcChip, RlcFixedTrace, RlcTrace, RLC_PHASE},
        RlpChip,
    },
    util::EthConfigParams,
    MPTConfig,
};
use core::iter::once;
use ethers_core::utils::keccak256;
use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::{
        circuit::{self, AssignedCell, Layouter, SimpleFloorPlanner, Value},
        plonk::{Assigned, Circuit, ConstraintSystem, Error},
    },
    utils::{bit_length, value_to_option, ScalarField},
    AssignedValue, Context, ContextCell,
    QuantumCell::Constant,
    SKIP_FIRST_PASS,
};
use itertools::Itertools;
use rayon::prelude::*;
use std::{cell::RefCell, collections::HashMap, env::set_var, iter, mem};
pub(crate) use zkevm_keccak::KeccakConfig;
use zkevm_keccak::{
    keccak_packed_multi::{
        get_num_keccak_f, get_num_rows_per_round, keccak_phase0, multi_keccak_phase1, KeccakRow,
        KeccakTable,
    },
    util::{eth_types::Field, NUM_BYTES_TO_SQUEEZE, NUM_ROUNDS, NUM_WORDS_TO_SQUEEZE, RATE},
};

#[cfg(feature = "halo2-axiom")]
type KeccakAssignedValue<'v, F> = AssignedCell<&'v Assigned<F>, F>;
#[cfg(not(feature = "halo2-axiom"))]
type KeccakAssignedValue<'v, F> = AssignedCell<F, F>;

mod builder;
#[cfg(test)]
mod tests;

pub use builder::*;
pub type FixedLenRLCs<F> = Vec<(RlcFixedTrace<F>, RlcFixedTrace<F>)>;
pub type VarLenRLCs<F> = Vec<(RlcTrace<F>, RlcFixedTrace<F>)>;

pub(crate) const KECCAK_CONTEXT_ID: usize = usize::MAX;

#[derive(Clone, Debug)]
pub struct KeccakFixedLenQuery<F: Field> {
    pub input_bytes: Vec<u8>,
    pub input_assigned: Vec<AssignedValue<F>>,

    pub output_bytes: [u8; NUM_BYTES_TO_SQUEEZE],
    pub output_assigned: Vec<AssignedValue<F>>,
}

#[derive(Clone, Debug)]
pub struct KeccakVarLenQuery<F: Field> {
    pub min_bytes: usize,
    pub max_bytes: usize,
    pub num_bytes: usize,
    // if `length` is `None`, then this is a fixed length keccak query
    // and it is assumed `min_bytes = max_bytes`
    pub length: AssignedValue<F>,
    pub input_bytes: Vec<u8>,
    pub input_assigned: Vec<AssignedValue<F>>,

    pub output_bytes: [u8; NUM_BYTES_TO_SQUEEZE],
    pub output_assigned: Vec<AssignedValue<F>>,
}

pub(crate) type SharedKeccakChip<F> = RefCell<KeccakChip<F>>;

/// `KeccakChip` plays the role both of the chip and something like a `KeccakThreadBuilder` in that it keeps a
/// list of the keccak queries that need to be linked with the external zkEVM keccak chip.
#[derive(Clone, Debug)]
pub struct KeccakChip<F: Field> {
    pub(crate) num_rows_per_round: usize,
    // available only in `FirstPhase`
    pub var_len_queries: Vec<KeccakVarLenQuery<F>>,
    pub fixed_len_queries: Vec<KeccakFixedLenQuery<F>>,
}

impl<F: Field> Default for KeccakChip<F> {
    fn default() -> Self {
        Self::new(get_num_rows_per_round())
    }
}

impl<F: Field> KeccakChip<F> {
    pub fn new(num_rows_per_round: usize) -> Self {
        Self { num_rows_per_round, var_len_queries: vec![], fixed_len_queries: vec![] }
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
    ///
    /// Returns the index in `self.fixed_len_queries` of the query.
    pub fn keccak_fixed_len(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        input_assigned: Vec<AssignedValue<F>>,
        input_bytes: Option<Vec<u8>>,
    ) -> usize {
        let bytes = input_bytes.unwrap_or_else(|| get_bytes(&input_assigned[..]));
        debug_assert_eq!(bytes.len(), input_assigned.len());

        let output_bytes = keccak256(&bytes);
        let output_assigned =
            ctx.assign_witnesses(output_bytes.iter().map(|b| gate.get_field_element(*b as u64)));

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
    /// Returns the index in `self.var_len_queries` of the query.
    pub fn keccak_var_len(
        &mut self,
        ctx: &mut Context<F>,
        range: &impl RangeInstructions<F>,
        input_assigned: Vec<AssignedValue<F>>,
        input_bytes: Option<Vec<u8>>,
        len: AssignedValue<F>,
        min_len: usize,
    ) -> usize {
        let bytes = input_bytes.unwrap_or_else(|| get_bytes(&input_assigned[..]));
        let max_len = input_assigned.len();

        range.check_less_than_safe(ctx, len, (max_len + 1) as u64);
        if min_len != 0 {
            range.check_less_than(
                ctx,
                Constant(range.gate().get_field_element((min_len - 1) as u64)),
                len,
                bit_length((max_len + 1) as u64),
            );
        }
        let num_bytes = len.value().get_lower_32() as usize;
        debug_assert!(bytes.len() >= num_bytes);
        let output_bytes = keccak256(&bytes[..num_bytes]);
        let output_assigned = ctx.assign_witnesses(
            output_bytes.iter().map(|b| range.gate().get_field_element(*b as u64)),
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
    /// Returns the merkle tree root as a byte array.
    ///
    /// # Assumptions
    /// - `leaves.len()` is a power of two.
    /// - Each element of `leaves` is a slice of assigned byte values.
    /// - The byte length of each element of `leaves` is known and fixed, i.e., we use `keccak_fixed_len` to perform the hashes.
    ///
    /// # Warning
    /// - This implementation currently has no domain separation between hashing leaves versus hashing inner nodes
    pub fn merkle_tree_root(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
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
            .into_iter()
            .map(|pair| {
                let leaves_concat = [pair[0].as_ref(), pair[1].as_ref()].concat();
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
    /// as a length `log_2(leaves.len()) + 1` vector of byte arrays.
    /// The mountain range is ordered with the largest mountain first. For example, if `num_leaves = leaves.len()` then the first mountain is the merkle root of the full tree.
    /// For `i` where `(num_leaves >> i) & 1 == 0`, the value of the corresponding peak should be considered UNDEFINED.
    ///
    /// The merkle root of the tree with leaves `leaves[..num_leaves]` can be recovered by successively hashing the elements in the merkle mountain range, in reverse order, corresponding to indices
    /// where `num_leaves` has a 1 bit.
    pub fn merkle_mountain_range(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
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
        once(self.merkle_tree_root(ctx, gate, leaves))
            .chain(num_leaves_bits.iter().enumerate().rev().skip(1).map(|(depth, &sel)| {
                let peak = self.merkle_tree_root(ctx, gate, &shift_leaves[..(1usize << depth)]);
                // no need to shift if we're at the end
                if depth != 0 {
                    // shift left by sel == 1 ? 2^depth : 0
                    for i in 0..1 << depth {
                        debug_assert_eq!(shift_leaves[i].len(), NUM_BYTES_TO_SQUEEZE);
                        for j in 0..shift_leaves[i].len() {
                            shift_leaves[i][j] = gate.select(
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

    fn capacity(&self) -> usize {
        self.fixed_len_queries
            .iter()
            .map(|q| q.input_assigned.len())
            .chain(self.var_len_queries.iter().map(|q| q.max_bytes))
            .map(get_num_keccak_f)
            .sum()
    }

    /// Wrapper that calls zkEVM Keccak chip for `FirstPhase` region assignments.
    ///
    /// Do this at the end of `FirstPhase` and then call `assign_phase1` in `SecondPhase`.
    pub fn assign_phase0(
        &self,
        region: &mut Region<F>,
        zkevm_keccak: &KeccakConfig<F>,
    ) -> Vec<[F; NUM_WORDS_TO_SQUEEZE]> {
        let mut squeeze_digests = Vec::with_capacity(self.capacity());
        let mut num_rows_used = 0;

        // Dummy first rows so that the initial data is absorbed
        // The initial data doesn't really matter, `is_final` just needs to be disabled.
        for (idx, row) in KeccakRow::dummy_rows(self.num_rows_per_round).iter().enumerate() {
            zkevm_keccak.set_row(region, idx, row);
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
                let max_keccak_f = get_num_keccak_f(query.max_bytes);
                let mut squeeze_digests = Vec::with_capacity(max_keccak_f);
                let mut rows =
                    Vec::with_capacity(max_keccak_f * (NUM_ROUNDS + 1) * self.num_rows_per_round);

                keccak_phase0(
                    &mut rows,
                    &mut squeeze_digests,
                    &query.input_bytes[..query.num_bytes],
                );
                // we generate extra keccaks so the number of keccak_f performed equals max_keccak_f
                // due to padding, each keccak([]) will do exactly one keccak_f and produce one squeeze digest
                let mut filler: Vec<_> = (num_keccak_f..max_keccak_f)
                    .into_par_iter()
                    .map(|_| {
                        let mut squeeze_digests = Vec::with_capacity(1);
                        let mut rows =
                            Vec::with_capacity((NUM_ROUNDS + 1) * self.num_rows_per_round);
                        keccak_phase0(&mut rows, &mut squeeze_digests, &[]);
                        (rows, squeeze_digests)
                    })
                    .collect();
                for filler in filler.iter_mut() {
                    rows.append(&mut filler.0);
                    squeeze_digests.append(&mut filler.1);
                }
                debug_assert_eq!(squeeze_digests.len(), max_keccak_f);
                (rows, squeeze_digests)
            })
            .collect::<Vec<_>>();

        for (rows, squeezes) in artifacts_fixed.into_iter().chain(artifacts_var.into_iter()) {
            for row in rows {
                zkevm_keccak.set_row(region, num_rows_used, &row);
                num_rows_used += 1;
            }
            squeeze_digests.extend(squeezes);
        }
        squeeze_digests
    }

    /// Counterpart of `assign_phase1`. Wrapper that calls zkEVM Keccak chip for `SecondPhase` region assignments.
    ///
    /// This loads the `KeccakTable` and produces the table of input and output RLCs squeezed out per keccak_f.
    /// We also translate these tables, which are of type Halo2 [`AssignedCell`] into our internal [`AssignedValue`] type.
    ///
    /// We assume this function is the first time Context ID [`KECCAK_CONTEXT_ID`] is used in the circuit.
    #[allow(clippy::type_complexity)]
    pub fn assign_phase1(
        &self,
        region: &mut Region<F>,
        keccak_table: &KeccakTable,
        squeeze_digests: Vec<[F; NUM_WORDS_TO_SQUEEZE]>,
        challenge_value: F,
        assigned_advices: Option<HashMap<(usize, usize), (circuit::Cell, usize)>>,
    ) -> (
        HashMap<(usize, usize), (circuit::Cell, usize)>,
        Vec<AssignedValue<F>>,
        Vec<AssignedValue<F>>,
    ) {
        let witness_gen_only = assigned_advices.is_none();
        let mut assigned_advices = assigned_advices.unwrap_or_default();
        // the input and output rlcs in the keccak table
        let empty: &[u8] = &[];
        let (table_input_rlcs, table_output_rlcs) = multi_keccak_phase1(
            region,
            keccak_table,
            self.fixed_len_queries.iter().map(|query| &query.input_bytes[..]).chain(
                self.var_len_queries.iter().flat_map(|query| {
                    let num_keccak_f = get_num_keccak_f(query.num_bytes);
                    let max_keccak_f = get_num_keccak_f(query.max_bytes);
                    iter::once(&query.input_bytes[..query.num_bytes])
                        .chain(iter::repeat(empty).take(max_keccak_f - num_keccak_f))
                }),
            ),
            Value::known(challenge_value),
            squeeze_digests,
        );
        // the above are external `AssignedCell`s, we need to convert them to internal `AssignedValue`s
        let mut upload_cells = |acells: Vec<KeccakAssignedValue<F>>,
                                offset|
         -> Vec<AssignedValue<F>> {
            acells
                .into_iter()
                .enumerate()
                .map(|(i, acell)| {
                    let value = value_to_option(acell.value())
                        .map(|v| {
                            #[cfg(feature = "halo2-axiom")]
                            {
                                **v
                            }
                            #[cfg(not(feature = "halo2-axiom"))]
                            {
                                Assigned::Trivial(*v)
                            }
                        })
                        .unwrap_or_else(|| Assigned::Trivial(F::zero())); // for keygen
                    let aval = AssignedValue {
                        value,
                        cell: (!witness_gen_only).then_some(ContextCell {
                            context_id: KECCAK_CONTEXT_ID,
                            offset: offset + i,
                        }),
                    };
                    if !witness_gen_only {
                        // we set row_offset = usize::MAX because you should never be directly using lookup on such a cell
                        #[cfg(feature = "halo2-axiom")]
                        assigned_advices
                            .insert((KECCAK_CONTEXT_ID, offset + i), (*acell.cell(), usize::MAX));
                        #[cfg(not(feature = "halo2-axiom"))]
                        assigned_advices
                            .insert((KECCAK_CONTEXT_ID, offset + i), (acell.cell(), usize::MAX));
                    }
                    aval
                })
                .collect::<Vec<_>>()
        };

        let table_input_rlcs = upload_cells(table_input_rlcs, 0);
        let table_output_rlcs = upload_cells(table_output_rlcs, table_input_rlcs.len());

        (assigned_advices, table_input_rlcs, table_output_rlcs)
    }

    /// Takes the translated `KeccakTable` of input and output RLCs, produced by the external zkEVM Keccak,
    /// and constrains that the RLCs equal the internally computed RLCs from the byte string witnesses.
    /// This is what guarantees that the internal byte string witnesses we use as keccak input/outputs actually
    /// correspond to correctly computed keccak hashes.
    pub fn process_phase1(
        &mut self,
        thread_pool: &mut RlcThreadBuilder<F>,
        rlc: &RlcChip<F>,
        range: &RangeChip<F>,
        table_input_rlcs: Vec<AssignedValue<F>>,
        table_output_rlcs: Vec<AssignedValue<F>>,
    ) -> (FixedLenRLCs<F>, VarLenRLCs<F>) {
        let witness_gen_only = thread_pool.witness_gen_only();
        let gate = range.gate();
        let (fixed_len_rlcs, var_len_rlcs) = self.compute_all_rlcs(thread_pool, rlc, gate);

        let mut keccak_f_index = 0;
        let ctx = thread_pool.gate_builder.main(0); // this ctx only used for equality constraints, so doesn't matter which phase. If we used phase 1 and it was the only empty ctx, currently it causes a panic in `assign_all`
                                                    // we know exactly where the fixed length squeezed RLCs are in the table, so it's straightforward to fetch
        for (input_rlc, output_rlc) in &fixed_len_rlcs {
            keccak_f_index += get_num_keccak_f(input_rlc.len);

            ctx.constrain_equal(&table_input_rlcs[keccak_f_index - 1], &input_rlc.rlc_val);
            ctx.constrain_equal(&table_output_rlcs[keccak_f_index - 1], &output_rlc.rlc_val);
        }
        // ctx dropped now

        assert_eq!(self.var_len_queries.len(), var_len_rlcs.len());
        // some additional selection logic is needed for fetching the correct hash for variable length
        // for each variable length keccak query, we select the correct keccak_f squeeze digest from a possible range of keccak_f's
        let var_selects = self
            .var_len_queries
            .iter()
            .map(|query| {
                let min_keccak_f = get_num_keccak_f(query.min_bytes);
                let max_keccak_f = get_num_keccak_f(query.max_bytes);
                // query.length is variable
                let select_range = keccak_f_index + min_keccak_f - 1..keccak_f_index + max_keccak_f;
                // we want to select index `keccak_f_index + get_num_keccak_f(query.length) - 1` where `query.length` is variable
                // this is the same as selecting `idx = get_num_keccak_f(query.length) - min_keccak_f` from `select_range`

                // num_keccak_f = length / RATE + 1
                let idx = (select_range.len() > 1).then(|| {
                    let ctx = thread_pool.gate_builder.main(RLC_PHASE);
                    let (len_div_rate, _) =
                        range.div_mod(ctx, query.length, RATE, bit_length(query.max_bytes as u64));
                    gate.sub(
                        ctx,
                        len_div_rate,
                        Constant(gate.get_field_element(min_keccak_f as u64 - 1)),
                    )
                });
                keccak_f_index += max_keccak_f;
                (select_range, idx)
            })
            .collect_vec();

        // multiple-thread selecting of correct rlc from keccak table
        let ctx_ids = (0..var_selects.len()).map(|_| thread_pool.get_new_thread_id()).collect_vec();
        let mut ctxs = ctx_ids
            .into_par_iter()
            .zip(var_selects.into_par_iter())
            .zip(var_len_rlcs.par_iter())
            .map(|((ctx_id, (select_range, idx)), (input_rlc, output_rlc))| {
                let mut ctx = Context::new(witness_gen_only, ctx_id);
                let (table_input_rlc, table_output_rlc) = if let Some(idx) = idx {
                    let indicator = gate.idx_to_indicator(&mut ctx, idx, select_range.len());
                    let input_rlc = gate.select_by_indicator(
                        &mut ctx,
                        table_input_rlcs[select_range.clone()].iter().copied(),
                        indicator.iter().copied(),
                    );
                    let output_rlc = gate.select_by_indicator(
                        &mut ctx,
                        table_output_rlcs[select_range].iter().copied(),
                        indicator,
                    );
                    (input_rlc, output_rlc)
                } else {
                    debug_assert_eq!(select_range.len(), 1);
                    (table_input_rlcs[select_range.start], table_output_rlcs[select_range.start])
                };
                // Define the dynamic RLC: RLC(a, l) = \sum_{i = 0}^{l - 1} a_i r^{l - 1 - i}
                // For a variable length RLC, we only have a1 = a2 if RLC(a1, l1) = RLC(a2, l2) AND l1 = l2.
                // In general, the length constraint is necessary because a1, a2 can have leading zeros.
                // However, I think it is not necessary in this case because if a1, a2 have the same RLC,
                // then they only differ in leading zeros. Since the zkevm-keccak pads the input with trailing bits,
                // this leads to the padded input being different in the two cases, which would lead to different outputs.
                ctx.constrain_equal(&input_rlc.rlc_val, &table_input_rlc);
                ctx.constrain_equal(&output_rlc.rlc_val, &table_output_rlc);

                ctx
            })
            .collect::<Vec<_>>();
        thread_pool.gate_builder.threads[RLC_PHASE].append(&mut ctxs);

        (fixed_len_rlcs, var_len_rlcs)
    }

    pub(crate) fn compute_all_rlcs(
        &mut self,
        thread_pool: &mut RlcThreadBuilder<F>,
        rlc: &RlcChip<F>,
        gate: &GateChip<F>,
    ) -> (FixedLenRLCs<F>, VarLenRLCs<F>) {
        let witness_gen_only = thread_pool.witness_gen_only();
        // multi-threaded computation of fixed-length RLCs
        let ctx_ids = (0..self.fixed_len_queries.len())
            .map(|_| thread_pool.get_new_thread_id())
            .collect_vec();
        let (mut ctxs, fixed_len_rlcs): (Vec<_>, Vec<_>) = self
            .fixed_len_queries
            .par_iter_mut()
            .zip(ctx_ids.into_par_iter())
            .map(|(query, rlc_id)| {
                let mut ctx_rlc = Context::new(witness_gen_only, rlc_id);
                let input = mem::take(&mut query.input_assigned);
                let output = mem::take(&mut query.output_assigned);
                let input_rlc = rlc.compute_rlc_fixed_len(&mut ctx_rlc, input);
                let output_rlc = rlc.compute_rlc_fixed_len(&mut ctx_rlc, output);
                (ctx_rlc, (input_rlc, output_rlc))
            })
            .unzip();
        thread_pool.threads_rlc.append(&mut ctxs);

        // multi-threaded computation of variable-length RLCs
        let ctx_ids = (0..self.var_len_queries.len())
            .map(|_| (thread_pool.get_new_thread_id(), thread_pool.get_new_thread_id()))
            .collect_vec();
        let (ctxs, var_len_rlcs): (Vec<_>, Vec<_>) = self
            .var_len_queries
            .par_iter_mut()
            .zip(ctx_ids.into_par_iter())
            .map(|(query, (gate_id, rlc_id))| {
                let mut ctx_gate = Context::new(witness_gen_only, gate_id);
                let mut ctx_rlc = Context::new(witness_gen_only, rlc_id);
                let input = mem::take(&mut query.input_assigned);
                let output = mem::take(&mut query.output_assigned);
                let input_rlc =
                    rlc.compute_rlc((&mut ctx_gate, &mut ctx_rlc), gate, input, query.length);
                let output_rlc = rlc.compute_rlc_fixed_len(&mut ctx_rlc, output);
                ((ctx_gate, ctx_rlc), (input_rlc, output_rlc))
            })
            .unzip();
        let (mut ctxs_gate, mut ctxs_rlc): (Vec<_>, Vec<_>) = ctxs.into_iter().unzip();
        thread_pool.gate_builder.threads[RLC_PHASE].append(&mut ctxs_gate);
        thread_pool.threads_rlc.append(&mut ctxs_rlc);

        (fixed_len_rlcs, var_len_rlcs)
    }
}

// convert field values to u8:
pub fn get_bytes<F: ScalarField>(bytes_assigned: &[AssignedValue<F>]) -> Vec<u8> {
    // TODO: if we really wanted to optimize, we can pre-compute a HashMap<F, u8> containing just `F::from(byte as u64)` for each byte. I think the cost of hashing is still cheaper than performing the Montgomery reduction
    bytes_assigned.iter().map(|abyte| abyte.value().get_lower_32() as u8).collect_vec()
}

pub(crate) fn rows_per_round(max_rows: usize, num_keccak_f: usize) -> usize {
    use zkevm_keccak::util::NUM_WORDS_TO_ABSORB;

    log::info!("Number of keccak_f permutations: {num_keccak_f}");
    let rows_per_round = max_rows / (num_keccak_f * (NUM_ROUNDS + 1) + 1 + NUM_WORDS_TO_ABSORB);
    log::info!("Optimal keccak rows per round: {rows_per_round}");
    rows_per_round
}

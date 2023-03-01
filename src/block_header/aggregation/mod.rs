use std::{
    env::{set_var, var},
    mem,
};

use crate::{block_header::EthBlockHeaderChainInstance, Field};
#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::{
        builder::{CircuitBuilderStage, MultiPhaseThreadBreakPoints},
        GateInstructions, RangeChip, RangeInstructions,
    },
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
    utils::ScalarField,
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use itertools::Itertools;
use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, Snark, LIMBS, SHPLONK};

mod final_merkle;
pub use final_merkle::*;

#[derive(Clone, Debug)]
pub struct EthBlockHeaderChainAggregationCircuit {
    // aggregation circuit with `instances` the accumulator (two G1 points) for delayed pairing verification
    num_blocks: u32,
    snarks: Vec<Snark>,
    pub max_depth: usize,
    pub initial_depth: usize,
    // because the aggregation circuit doesn't have a keccak chip, in the mountain range
    // vector we will store the `2^{max_depth - initial_depth}` "new roots" as well as the length `initial_depth` mountain range tail, which determines the smallest entries in the mountain range.
    #[cfg(debug_assertions)]
    pub chain_instance: EthBlockHeaderChainInstance,
}

impl EthBlockHeaderChainAggregationCircuit {
    /// `snarks` should be exactly two snarks of either
    /// - `EthBlockHeaderChainCircuit` if `max_depth == initial_depth + 1` or
    /// - `EthBlockHeaderChainAggregationCircuit` otherwise
    ///
    /// Assumes `num_blocks > 0`.
    pub fn new(
        snarks: Vec<Snark>,
        num_blocks: u32,
        max_depth: usize,
        initial_depth: usize,
    ) -> Self {
        assert_ne!(num_blocks, 0);
        assert_eq!(snarks.len(), 2);
        assert!(max_depth > initial_depth);
        assert!(num_blocks <= 1 << max_depth);

        #[cfg(debug_assertions)]
        let chain_instance = {
            // OLD, no longer needed except for debugging
            // basically the same logic as `join_previous_instances` except in native rust
            let instance_start_idx = usize::from(initial_depth + 1 != max_depth) * 4 * LIMBS;
            let [instance0, instance1] = [0, 1].map(|i| {
                EthBlockHeaderChainInstance::from_instance(
                    &snarks[i].instances[0][instance_start_idx..],
                )
            });

            let mut roots = Vec::with_capacity((1 << (max_depth - initial_depth)) + initial_depth);
            let cutoff = 1 << (max_depth - initial_depth - 1);
            roots.extend_from_slice(&instance0.merkle_mountain_range[..cutoff]);
            roots.extend_from_slice(&instance1.merkle_mountain_range[..cutoff]);
            if num_blocks <= 1 << (max_depth - 1) {
                assert_eq!(
                    instance0.end_block_number - instance0.start_block_number,
                    num_blocks - 1
                );
                roots.extend_from_slice(&instance0.merkle_mountain_range[cutoff..]);
            } else {
                assert_eq!(instance0.end_hash, instance1.prev_hash);
                assert_eq!(
                    instance0.end_block_number - instance0.start_block_number,
                    (1 << (max_depth - 1)) - 1
                );
                assert_eq!(instance0.end_block_number, instance1.start_block_number - 1);
                assert_eq!(
                    instance1.end_block_number - instance0.start_block_number,
                    num_blocks - 1
                );
                roots.extend_from_slice(&instance1.merkle_mountain_range[cutoff..]);
            };
            EthBlockHeaderChainInstance {
                prev_hash: instance0.prev_hash,
                end_hash: if num_blocks <= 1 << (max_depth - 1) {
                    instance0.end_hash
                } else {
                    instance1.end_hash
                },
                start_block_number: instance0.start_block_number,
                end_block_number: instance0.start_block_number + num_blocks - 1,
                merkle_mountain_range: roots,
            }
        };
        Self {
            snarks,
            num_blocks,
            max_depth,
            initial_depth,
            #[cfg(debug_assertions)]
            chain_instance,
        }
    }

    /// `params` should be the universal trusted setup for the present aggregation circuit.
    /// We assume the trusted setup for the previous SNARKs is compatible with `params` in the sense that
    /// the generator point and toxic waste `tau` are the same.
    pub fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
    ) -> AggregationCircuit {
        let num_blocks = self.num_blocks;
        let max_depth = self.max_depth;
        let initial_depth = self.initial_depth;
        #[cfg(feature = "display")]
        let timer = start_timer!(|| {
            format!("New EthBlockHeaderChainAggregationCircuit | num_blocks: {num_blocks} | max_depth: {max_depth} | initial_depth: {initial_depth}")
        });
        let mut aggregation = AggregationCircuit::new::<SHPLONK>(
            stage,
            break_points,
            lookup_bits,
            params,
            self.snarks,
        );
        // TODO: should reuse RangeChip from aggregation circuit, but can't refactor right now
        let range = RangeChip::<Fr>::default(lookup_bits);
        let mut builder = aggregation.inner.circuit.0.builder.borrow_mut();
        let ctx = builder.main(0);
        let num_blocks_minus_one =
            ctx.load_witness(range.gate().get_field_element(num_blocks as u64 - 1));
        let mut new_instances = join_previous_instances(
            ctx,
            &range,
            mem::take(&mut aggregation.previous_instances).try_into().unwrap(),
            num_blocks_minus_one,
            max_depth,
            initial_depth,
        );
        drop(builder);
        aggregation.inner.assigned_instances.append(&mut new_instances);
        #[cfg(feature = "display")]
        end_timer!(timer);

        match stage {
            CircuitBuilderStage::Prover => {}
            _ => {
                let minimum_rows =
                    var("UNUSABLE_ROWS").map(|s| s.parse().unwrap_or(10)).unwrap_or(10);
                set_var("LOOKUP_BITS", lookup_bits.to_string());
                aggregation.config(params.k(), Some(minimum_rows));
            }
        }
        aggregation
    }

    /// The number of instances NOT INCLUDING the accumulator
    pub fn get_num_instance(max_depth: usize, initial_depth: usize) -> usize {
        debug_assert!(max_depth >= initial_depth);
        5 + 2 * ((1 << (max_depth - initial_depth)) + initial_depth)
    }
}

/// Takes the concatenated previous instances from two `EthBlockHeaderChainAggregationCircuit`s
/// of max depth `max_depth - 1` and  
/// - checks that they form a chain of `max_depth`
/// - updates the merkle mountain range:
///     - stores the latest `2^{max_depth - initial_depth}` roots for keccak later
///     - selects the correct last `initial_depth` roots for the smallest part of the range
///
/// Returns the new instances for the depth `max_depth` circuit (without accumulators)
pub fn join_previous_instances<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    prev_instances: [Vec<AssignedValue<F>>; 2],
    num_blocks_minus_one: AssignedValue<F>,
    max_depth: usize,
    initial_depth: usize,
) -> Vec<AssignedValue<F>> {
    let prev_depth = max_depth - 1;
    let non_accumulator_start = if prev_depth != initial_depth { 4 * LIMBS } else { 0 };
    let num_instance =
        EthBlockHeaderChainAggregationCircuit::get_num_instance(prev_depth, initial_depth)
            + non_accumulator_start;
    debug_assert_eq!(num_instance, prev_instances[0].len());
    debug_assert_eq!(num_instance, prev_instances[1].len());

    let instance0 = &prev_instances[0][non_accumulator_start..];
    let instance1 = &prev_instances[1][non_accumulator_start..];
    let mountain_selector = range.is_less_than_safe(ctx, num_blocks_minus_one, 1u64 << prev_depth);

    // join block hashes
    let prev_hash = &instance0[..2];
    let intermed_hash0 = &instance0[2..4];
    let intermed_hash1 = &instance1[..2];
    let end_hash = &instance1[2..4];
    for (a, b) in intermed_hash0.iter().zip(intermed_hash1.iter()) {
        // a == b || num_blocks <= 2^prev_depth
        let mut eq_check = range.gate().is_equal(ctx, *a, *b);
        eq_check = range.gate().or(ctx, eq_check, mountain_selector);
        range.gate().assert_is_const(ctx, &eq_check, &F::one());
    }
    let end_hash = intermed_hash0
        .iter()
        .zip(end_hash.iter())
        .map(|(a, b)| range.gate().select(ctx, *a, *b, mountain_selector))
        .collect_vec();

    // join & sanitize block numbers
    let (start_block_number, intermed_block_num0) = split_u64_into_u32s(ctx, range, instance0[4]);
    let (intermed_block_num1, mut end_block_number) = split_u64_into_u32s(ctx, range, instance1[4]);
    let num_blocks0_minus_one = range.gate().sub(ctx, intermed_block_num0, start_block_number);
    let num_blocks1_minus_one = range.gate().sub(ctx, end_block_number, intermed_block_num1);
    range.check_less_than_safe(ctx, num_blocks0_minus_one, 1 << prev_depth);
    range.check_less_than_safe(ctx, num_blocks1_minus_one, 1 << prev_depth);

    end_block_number =
        range.gate().select(ctx, intermed_block_num0, end_block_number, mountain_selector);
    // make sure chains link up
    let next_block_num0 = range.gate().add(ctx, intermed_block_num0, Constant(F::one()));
    let mut eq_check = range.gate().is_equal(ctx, next_block_num0, intermed_block_num1);
    eq_check = range.gate().or(ctx, eq_check, mountain_selector);
    range.gate().assert_is_const(ctx, &eq_check, &F::one());
    // if num_blocks > 2^prev_depth, then num_blocks0 must equal 2^prev_depth
    let prev_max_blocks = range.gate().pow_of_two()[prev_depth];
    let is_max_depth0 =
        range.gate().is_equal(ctx, num_blocks0_minus_one, Constant(prev_max_blocks - F::one()));
    eq_check = range.gate().or(ctx, is_max_depth0, mountain_selector);
    range.gate().assert_is_const(ctx, &eq_check, &F::one());
    // check number of blocks is correct
    let boundary_num_diff = range.gate().sub(ctx, end_block_number, start_block_number);
    ctx.constrain_equal(&boundary_num_diff, &num_blocks_minus_one);
    // concatenate block numbers
    let boundary_block_numbers = range.gate().mul_add(
        ctx,
        Constant(range.gate().pow_of_two()[32]),
        start_block_number,
        end_block_number,
    );

    // update merkle roots
    let roots0 = &instance0[5..];
    let roots1 = &instance1[5..];
    let cutoff = 2 * (1 << (prev_depth - initial_depth));

    // join merkle mountain ranges
    let mut instances = Vec::with_capacity(num_instance + cutoff);
    instances.extend_from_slice(prev_hash);
    instances.extend_from_slice(&end_hash);
    instances.push(boundary_block_numbers);
    instances.extend_from_slice(&roots0[..cutoff]);
    instances.extend_from_slice(&roots1[..cutoff]);
    instances.extend(
        roots0[cutoff..]
            .iter()
            .zip(roots1[cutoff..].iter())
            .map(|(a, b)| range.gate().select(ctx, *a, *b, mountain_selector)),
    );

    instances
}

fn split_u64_into_u32s<F: ScalarField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    num: AssignedValue<F>,
) -> (AssignedValue<F>, AssignedValue<F>) {
    let v = num.value().get_lower_128() as u64;
    let first = F::from(v >> 32);
    let second = F::from(v & u32::MAX as u64);
    ctx.assign_region(
        [Witness(second), Witness(first), Constant(range.gate().pow_of_two()[32]), Existing(num)],
        [0],
    );
    let second = ctx.get(-4);
    let first = ctx.get(-3);
    for limb in [first, second] {
        range.range_check(ctx, limb, 32);
    }
    (first, second)
}

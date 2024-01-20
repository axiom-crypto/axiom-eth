//! Intermediate aggregation circuits that aggregate in a binary tree topology:
//! The leaves of the tree are formed by [crate::header_chain::EthBlockHeaderChainCircuit]s, and intermediate notes
//! of the tree are formed by [EthBlockHeaderChainIntermediateAggregationCircuit]s.
//!
//! An [EthBlockHeaderChainIntermediateAggregationCircuit] can aggregate either:
//! - two [crate::header_chain::EthBlockHeaderChainCircuit]s or
//! - two [EthBlockHeaderChainIntermediateAggregationCircuit]s.
//!
//! The root of the aggregation tree will be a [super::final_merkle::EthBlockHeaderChainRootAggregationCircuit].
//! The difference between Intermediate and Root aggregation circuits is that the Intermediate ones
//! do not have a keccak sub-circuit: all keccaks are delayed until the Root aggregation.
use anyhow::{bail, Result};
use axiom_eth::{
    halo2_base::{
        gates::{circuit::CircuitBuilderStage, GateInstructions, RangeChip, RangeInstructions},
        utils::ScalarField,
        AssignedValue, Context,
        QuantumCell::{Constant, Existing, Witness},
    },
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr},
        poly::kzg::commitment::ParamsKZG,
    },
    snark_verifier_sdk::{
        halo2::aggregation::{AggregationCircuit, VerifierUniversality},
        Snark, SHPLONK,
    },
    utils::snark_verifier::{
        get_accumulator_indices, AggregationCircuitParams, NUM_FE_ACCUMULATOR,
    },
};
use itertools::Itertools;

use crate::Field;

/// Newtype to distinguish an aggregation circuit created from [EthBlockHeaderChainIntermediateAggregationInput]
pub struct EthBlockHeaderChainIntermediateAggregationCircuit(pub AggregationCircuit);

impl EthBlockHeaderChainIntermediateAggregationCircuit {
    /// The number of instances NOT INCLUDING the accumulator
    pub fn get_num_instance(max_depth: usize, initial_depth: usize) -> usize {
        assert!(max_depth >= initial_depth);
        5 + 2 * ((1 << (max_depth - initial_depth)) + initial_depth)
    }
}

/// The input to create an intermediate [AggregationCircuit] that aggregates [crate::header_chain::EthBlockHeaderChainCircuit]s.
/// These are intemediate aggregations because they do not perform additional keccaks. Therefore the public instance format (after excluding accumulators) is
/// different from that of the original [crate::header_chain::EthBlockHeaderChainCircuit]s.
#[derive(Clone, Debug)]
pub struct EthBlockHeaderChainIntermediateAggregationInput {
    // aggregation circuit with `instances` the accumulator (two G1 points) for delayed pairing verification
    pub num_blocks: u32,
    /// `snarks` should be exactly two snarks of either
    /// - `EthBlockHeaderChainCircuit` if `max_depth == initial_depth + 1` or
    /// - `EthBlockHeaderChainIntermediateAggregationCircuit` (this circuit) otherwise
    ///
    /// Assumes `num_blocks > 0`.
    pub snarks: Vec<Snark>,
    pub max_depth: usize,
    pub initial_depth: usize,
    // because the aggregation circuit doesn't have a keccak chip, in the mountain range
    // vector we will store the `2^{max_depth - initial_depth}` "new roots" as well as the length `initial_depth` mountain range tail, which determines the smallest entries in the mountain range.
}

impl EthBlockHeaderChainIntermediateAggregationInput {
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

        Self { snarks, num_blocks, max_depth, initial_depth }
    }
}

impl EthBlockHeaderChainIntermediateAggregationInput {
    pub fn build(
        self,
        stage: CircuitBuilderStage,
        circuit_params: AggregationCircuitParams,
        kzg_params: &ParamsKZG<Bn256>,
    ) -> Result<EthBlockHeaderChainIntermediateAggregationCircuit> {
        let num_blocks = self.num_blocks;
        let max_depth = self.max_depth;
        let initial_depth = self.initial_depth;
        log::info!(
            "New EthBlockHeaderChainAggregationCircuit | num_blocks: {num_blocks} | max_depth: {max_depth} | initial_depth: {initial_depth}"
        );
        let prev_acc_indices = get_accumulator_indices(&self.snarks);
        if self.max_depth == self.initial_depth + 1
            && prev_acc_indices.iter().any(|indices| !indices.is_empty())
        {
            bail!("Snarks to be aggregated must not have accumulators: they should come from EthBlockHeaderChainCircuit");
        }
        if self.max_depth > self.initial_depth + 1
            && prev_acc_indices.iter().any(|indices| indices.len() != NUM_FE_ACCUMULATOR)
        {
            bail!("Snarks to be aggregated must all be EthBlockHeaderChainIntermediateAggregationCircuits");
        }
        let mut circuit = AggregationCircuit::new::<SHPLONK>(
            stage,
            circuit_params,
            kzg_params,
            self.snarks,
            VerifierUniversality::None,
        );
        let mut prev_instances = circuit.previous_instances().clone();
        // remove old accumulators
        for (prev_instance, acc_indices) in prev_instances.iter_mut().zip_eq(prev_acc_indices) {
            for i in acc_indices.into_iter().sorted().rev() {
                prev_instance.remove(i);
            }
        }

        let builder = &mut circuit.builder;
        // TODO: slight computational overhead from recreating RangeChip; builder should store RangeChip as OnceCell
        let range = builder.range_chip();
        let ctx = builder.main(0);
        let num_blocks_minus_one = ctx.load_witness(Fr::from(num_blocks as u64 - 1));

        let new_instances = join_previous_instances::<Fr>(
            ctx,
            &range,
            prev_instances.try_into().unwrap(),
            num_blocks_minus_one,
            max_depth,
            initial_depth,
        );
        if builder.assigned_instances.len() != 1 {
            bail!("should only have 1 instance column");
        }
        assert_eq!(builder.assigned_instances[0].len(), NUM_FE_ACCUMULATOR);
        builder.assigned_instances[0].extend(new_instances);

        Ok(EthBlockHeaderChainIntermediateAggregationCircuit(circuit))
    }
}

/// Takes the concatenated previous instances from two `EthBlockHeaderChainIntermediateAggregationCircuit`s
/// of max depth `max_depth - 1` and
/// - checks that they form a chain of `max_depth`
/// - updates the merkle mountain range:
///     - stores the latest `2^{max_depth - initial_depth}` roots for keccak later
///     - selects the correct last `initial_depth` roots for the smallest part of the range
///
/// If `max_depth - 1 == initial_depth`, then the previous instances are from two `EthBlockHeaderChainCircuit`s.
///
/// Returns the new instances for the depth `max_depth` circuit (without accumulators)
///
/// ## Assumptions
/// - `prev_instances` are the previous instances **with old accumulators removed**.
pub fn join_previous_instances<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    prev_instances: [Vec<AssignedValue<F>>; 2],
    num_blocks_minus_one: AssignedValue<F>,
    max_depth: usize,
    initial_depth: usize,
) -> Vec<AssignedValue<F>> {
    let prev_depth = max_depth - 1;
    let num_instance = EthBlockHeaderChainIntermediateAggregationCircuit::get_num_instance(
        prev_depth,
        initial_depth,
    );
    assert_eq!(num_instance, prev_instances[0].len());
    assert_eq!(num_instance, prev_instances[1].len());

    let [instance0, instance1] = prev_instances;
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
        range.gate().assert_is_const(ctx, &eq_check, &F::ONE);
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
    let next_block_num0 = range.gate().add(ctx, intermed_block_num0, Constant(F::ONE));
    let mut eq_check = range.gate().is_equal(ctx, next_block_num0, intermed_block_num1);
    eq_check = range.gate().or(ctx, eq_check, mountain_selector);
    range.gate().assert_is_const(ctx, &eq_check, &F::ONE);
    // if num_blocks > 2^prev_depth, then num_blocks0 must equal 2^prev_depth
    let prev_max_blocks = range.gate().pow_of_two()[prev_depth];
    let is_max_depth0 =
        range.gate().is_equal(ctx, num_blocks0_minus_one, Constant(prev_max_blocks - F::ONE));
    eq_check = range.gate().or(ctx, is_max_depth0, mountain_selector);
    range.gate().assert_is_const(ctx, &eq_check, &F::ONE);
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
    let v = num.value().get_lower_64();
    let first = F::from(v >> 32);
    let second = F::from(v & u32::MAX as u64);
    ctx.assign_region(
        [Witness(second), Witness(first), Constant(F::from(1u64 << 32)), Existing(num)],
        [0],
    );
    let second = ctx.get(-4);
    let first = ctx.get(-3);
    for limb in [first, second] {
        range.range_check(ctx, limb, 32);
    }
    (first, second)
}

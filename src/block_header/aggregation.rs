use super::EthBlockHeaderChainInstance;
use crate::Field;
#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::{range::RangeConfig, GateInstructions, RangeInstructions},
    halo2_proofs::{
        circuit::{Layouter, Region, SimpleFloorPlanner, Value},
        halo2curves::bn256::{Bn256, Fr},
        plonk::{Circuit, ConstraintSystem, Error},
        poly::kzg::commitment::ParamsKZG,
    },
    utils::{PrimeField, ScalarField},
    AssignedValue, Context, ContextParams,
    QuantumCell::{Constant, Existing, Witness},
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier_sdk::{
    halo2::aggregation::{
        aggregate, flatten_accumulator, AggregationCircuit, AggregationConfig, Halo2Loader,
    },
    CircuitExt, Snark, LIMBS,
};
use std::rc::Rc;

mod final_merkle;
pub use final_merkle::*;

#[derive(Clone)]
pub struct EthBlockHeaderChainAggregationCircuit {
    // aggregation circuit with `instances` the accumulator (two G1 points) for delayed pairing verification
    aggregation: AggregationCircuit,
    num_blocks: u32,
    // because the aggregation circuit doesn't have a keccak chip, in the mountain range
    // vector we will store the `2^{max_depth - initial_depth}` "new roots" as well as the length `initial_depth` mountain range tail, which determines the smallest entries in the mountain range.
    pub chain_instance: EthBlockHeaderChainInstance,
    pub max_depth: usize,
    pub initial_depth: usize,
}

impl EthBlockHeaderChainAggregationCircuit {
    /// `snarks` should be exactly two snarks of either
    /// - `EthBlockHeaderChainCircuit` if `max_depth == initial_depth + 1` or
    /// - `EthBlockHeaderChainAggregationCircuit` otherwise
    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks: Vec<Snark>,
        rng: &mut (impl Rng + Send),
        num_blocks: u32,
        max_depth: usize,
        initial_depth: usize,
    ) -> Self {
        assert_eq!(snarks.len(), 2);
        assert!(max_depth > initial_depth);
        assert!(num_blocks <= 1 << max_depth);

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
            assert_eq!(instance0.end_block_number - instance0.start_block_number, num_blocks - 1);
            roots.extend_from_slice(&instance0.merkle_mountain_range[cutoff..]);
        } else {
            assert_eq!(instance0.end_hash, instance1.prev_hash);
            assert_eq!(
                instance0.end_block_number - instance0.start_block_number,
                (1 << (max_depth - 1)) - 1
            );
            assert_eq!(instance0.end_block_number, instance1.start_block_number - 1);
            assert_eq!(instance1.end_block_number - instance0.start_block_number, num_blocks - 1);
            roots.extend_from_slice(&instance1.merkle_mountain_range[cutoff..]);
        };
        let chain_instance = EthBlockHeaderChainInstance {
            prev_hash: instance0.prev_hash,
            end_hash: if num_blocks <= 1 << (max_depth - 1) {
                instance0.end_hash
            } else {
                instance1.end_hash
            },
            start_block_number: instance0.start_block_number,
            end_block_number: instance0.start_block_number + num_blocks - 1,
            merkle_mountain_range: roots,
        };
        let aggregation = AggregationCircuit::new(params, snarks, rng);

        Self { aggregation, num_blocks, chain_instance, max_depth, initial_depth }
    }

    pub fn aggregate_and_join_instances<'v>(
        &self,
        config: &AggregationConfig,
        region: Region<'v, Fr>,
    ) -> (Vec<AssignedValue<'v, Fr>>, AssignedValue<'v, Fr>, Rc<Halo2Loader<'v>>) {
        let ctx = Context::new(
            region,
            ContextParams {
                max_rows: config.gate().max_rows,
                num_context_ids: 1,
                fixed_columns: config.gate().constants.clone(),
            },
        );
        let ecc_chip = config.ecc_chip();
        let loader = Halo2Loader::new(ecc_chip, ctx);
        let (prev_instances, acc) = aggregate::<Kzg<Bn256, Bdfg21>>(
            self.aggregation.succinct_verifying_key(),
            &loader,
            self.aggregation.snarks(),
            self.aggregation.as_proof(),
        );

        // for some reason the strong count of `loader` is >1, so to avoid unsafe code this is a hack to work with context
        let tmp = Rc::clone(&loader);
        let mut ctx = tmp.ctx_mut();

        let num_blocks_minus_one = config.gate().load_witness(
            &mut ctx,
            Value::known(config.gate().get_field_element(self.num_blocks as u64 - 1)),
        );
        let new_instances = join_previous_instances(
            &mut ctx,
            config.range(),
            &prev_instances,
            &num_blocks_minus_one,
            self.max_depth,
            self.initial_depth,
        );

        let new_instances = [flatten_accumulator(acc), new_instances].concat();
        (new_instances, num_blocks_minus_one, loader)
    }

    /// The number of instances NOT INCLUDING the accumulator
    pub fn get_num_instance(max_depth: usize, initial_depth: usize) -> usize {
        debug_assert!(max_depth >= initial_depth);
        5 + 2 * ((1 << (max_depth - initial_depth)) + initial_depth)
    }

    pub fn instance(&self) -> Vec<Fr> {
        [&self.aggregation.instances()[0], &self.chain_instance.to_instance()[..]].concat()
    }
}

impl Circuit<Fr> for EthBlockHeaderChainAggregationCircuit {
    type Config = AggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            aggregation: self.aggregation.without_witnesses(),
            num_blocks: self.num_blocks,
            chain_instance: self.chain_instance.clone(),
            max_depth: self.max_depth,
            initial_depth: self.initial_depth,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        AggregationCircuit::configure(meta)
    }

    fn synthesize(
        &self,
        config: AggregationConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        #[cfg(feature = "display")]
        let witness_time = start_timer!(|| format!(
            "synthesize {:06x}-{:06x} {} {}",
            self.chain_instance.start_block_number,
            self.chain_instance.end_block_number,
            self.max_depth,
            self.initial_depth
        ));
        config.range().load_lookup_table(&mut layouter).expect("load range lookup table");
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        let mut instances = Vec::new();
        layouter
            .assign_region(
                || "Block header chain aggregation circuit",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let (new_instances, _, loader) =
                        self.aggregate_and_join_instances(&config, region);
                    instances.extend(new_instances.iter().map(|assigned| assigned.cell()).cloned());
                    let ctx = &mut loader.ctx_mut();
                    config.base_field_config.finalize(ctx);

                    #[cfg(feature = "display")]
                    ctx.print_stats(&["Range"]);
                    Ok(())
                },
            )
            .unwrap();

        for (i, cell) in instances.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.instance, i);
        }
        #[cfg(feature = "display")]
        end_timer!(witness_time);
        Ok(())
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
pub fn join_previous_instances<'v, F: Field + PrimeField>(
    ctx: &mut Context<'v, F>,
    range: &RangeConfig<F>,
    prev_instances: &[AssignedValue<'v, F>],
    num_blocks_minus_one: &AssignedValue<'v, F>,
    max_depth: usize,
    initial_depth: usize,
) -> Vec<AssignedValue<'v, F>> {
    let prev_depth = max_depth - 1;
    let non_accumulator_start = if prev_depth != initial_depth { 4 * LIMBS } else { 0 };
    let num_instance =
        EthBlockHeaderChainAggregationCircuit::get_num_instance(prev_depth, initial_depth)
            + non_accumulator_start;
    assert_eq!(prev_instances.len(), num_instance * 2);

    let instance0 = &prev_instances[non_accumulator_start..num_instance];
    let instance1 = &prev_instances[num_instance + non_accumulator_start..];
    let mountain_selector = range.is_less_than_safe(ctx, num_blocks_minus_one, 1 << prev_depth);

    // join block hashes
    let prev_hash = &instance0[..2];
    let intermed_hash0 = &instance0[2..4];
    let intermed_hash1 = &instance1[..2];
    let end_hash = &instance1[2..4];
    for (a, b) in intermed_hash0.iter().zip(intermed_hash1.iter()) {
        // a == b || num_blocks <= 2^prev_depth
        let mut eq_check = range.gate().is_equal(ctx, Existing(a), Existing(b));
        eq_check = range.gate().or(ctx, Existing(&eq_check), Existing(&mountain_selector));
        range.gate().assert_is_const(ctx, &eq_check, F::one());
    }
    let end_hash = intermed_hash0
        .iter()
        .zip(end_hash.iter())
        .map(|(a, b)| {
            range.gate().select(ctx, Existing(a), Existing(b), Existing(&mountain_selector))
        })
        .collect_vec();

    // join & sanitize block numbers
    let (start_block_number, intermed_block_num0) = split_u64_into_u32s(ctx, range, &instance0[4]);
    let (intermed_block_num1, mut end_block_number) =
        split_u64_into_u32s(ctx, range, &instance1[4]);
    let num_blocks0_minus_one =
        range.gate().sub(ctx, Existing(&intermed_block_num0), Existing(&start_block_number));
    let num_blocks1_minus_one =
        range.gate().sub(ctx, Existing(&end_block_number), Existing(&intermed_block_num1));
    range.check_less_than_safe(ctx, &num_blocks0_minus_one, 1 << prev_depth);
    range.check_less_than_safe(ctx, &num_blocks1_minus_one, 1 << prev_depth);

    end_block_number = range.gate().select(
        ctx,
        Existing(&intermed_block_num0),
        Existing(&end_block_number),
        Existing(&mountain_selector),
    );
    // make sure chains link up
    let next_block_num0 = range.gate().add(ctx, Existing(&intermed_block_num0), Constant(F::one()));
    let mut eq_check =
        range.gate().is_equal(ctx, Existing(&next_block_num0), Existing(&intermed_block_num1));
    eq_check = range.gate().or(ctx, Existing(&eq_check), Existing(&mountain_selector));
    range.gate().assert_is_const(ctx, &eq_check, F::one());
    // if num_blocks > 2^prev_depth, then num_blocks0 must equal 2^prev_depth
    let prev_max_blocks = range.gate().pow_of_two()[prev_depth];
    let is_max_depth0 = range.gate().is_equal(
        ctx,
        Existing(&num_blocks0_minus_one),
        Constant(prev_max_blocks - F::one()),
    );
    eq_check = range.gate().or(ctx, Existing(&is_max_depth0), Existing(&mountain_selector));
    range.gate().assert_is_const(ctx, &eq_check, F::one());
    // check number of blocks is correct
    let boundary_num_diff =
        range.gate().sub(ctx, Existing(&end_block_number), Existing(&start_block_number));
    ctx.constrain_equal(&boundary_num_diff, num_blocks_minus_one);
    // concatenate block numbers
    let boundary_block_numbers = range.gate().mul_add(
        ctx,
        Constant(range.gate().pow_of_two()[32]),
        Existing(&start_block_number),
        Existing(&end_block_number),
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
    instances.extend(roots0[cutoff..].iter().zip(roots1[cutoff..].iter()).map(|(a, b)| {
        range.gate().select(ctx, Existing(a), Existing(b), Existing(&mountain_selector))
    }));

    instances
}

fn split_u64_into_u32s<'v, F: ScalarField>(
    ctx: &mut Context<'v, F>,
    range: &RangeConfig<F>,
    num: &AssignedValue<'v, F>,
) -> (AssignedValue<'v, F>, AssignedValue<'v, F>) {
    let mut first = Value::unknown();
    let mut second = Value::unknown();
    num.value().map(|v| {
        let v = v.get_lower_128() as u64;
        first = Value::known(F::from(v >> 32));
        second = Value::known(F::from(v & u32::MAX as u64));
    });
    let mut assignments = range
        .gate()
        .assign_region(
            ctx,
            vec![
                Witness(second),
                Witness(first),
                Constant(range.gate().pow_of_two()[32]),
                Existing(num),
            ],
            vec![(0, None)],
        )
        .into_iter();
    let second = assignments.next().unwrap();
    let first = assignments.next().unwrap();
    for limb in [&first, &second] {
        range.range_check(ctx, limb, 32);
    }
    (first, second)
}

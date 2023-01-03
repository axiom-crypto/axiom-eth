#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions},
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::{Bn256, Fr},
        plonk::{Circuit, ConstraintSystem, Error},
        poly::kzg::commitment::ParamsKZG,
    },
    QuantumCell::{Constant, Existing},
};

use crate::{
    block_header::EthBlockHeaderChainInstance,
    keccak::{KeccakChip, KeccakConfig},
    rlp::rlc::{RlcChip, RlcConfig},
    util::{bytes_be_to_u128, get_merkle_mountain_range, num_to_bytes_be, NUM_BYTES_IN_U128},
};
use itertools::Itertools;
use rand::Rng;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::{
    halo2::{
        aggregation::{AggregationConfig, AggregationConfigParams},
        PoseidonTranscript,
    },
    CircuitExt, NativeLoader, Snark, LIMBS,
};
use std::{
    env::{set_var, var},
    fs::File,
};

use super::EthBlockHeaderChainAggregationCircuit;

#[derive(Serialize, Deserialize)]
pub struct AggregationWithKeccakConfigParams {
    pub aggregation: AggregationConfigParams,
    pub num_rlc_columns: usize,
    pub unusable_rows: usize,
    pub keccak_rows_per_round: usize,
}
impl AggregationWithKeccakConfigParams {
    pub fn get() -> Self {
        let path = var("FINAL_AGGREGATION_CONFIG").expect("FINAL_AGGREGATION_CONFIG not set");
        serde_json::from_reader(
            File::open(&path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
        )
        .unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct AggregationWithKeccakConfig {
    pub keccak: KeccakConfig<Fr>,
    pub rlc: RlcConfig<Fr>,
    pub aggregation: AggregationConfig,
}

impl AggregationWithKeccakConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        params: AggregationWithKeccakConfigParams,
    ) -> Self {
        let degree = params.aggregation.degree;
        let mut aggregation = AggregationConfig::configure(meta, params.aggregation);
        set_var("KECCAK_DEGREE", degree.to_string());
        set_var("KECCAK_ROWS", params.keccak_rows_per_round.to_string());
        set_var("UNUSABLE_ROWS", params.unusable_rows.to_string());
        let rlc = RlcConfig::configure(meta, params.num_rlc_columns, 1);
        let keccak = KeccakConfig::new(meta, rlc.gamma);
        #[cfg(feature = "display")]
        println!("Unusable rows: {}", meta.minimum_rows());

        aggregation.base_field_config.range.gate.max_rows = (1 << degree) - meta.minimum_rows();
        Self { keccak, aggregation, rlc }
    }

    pub fn gate(&self) -> &FlexGateConfig<Fr> {
        self.aggregation.gate()
    }

    pub fn range(&self) -> &RangeConfig<Fr> {
        self.aggregation.range()
    }
}

/// Same as `EthBlockHeaderChainAggregationCircuit` but uses Keccak chip to compute the final merkle mountain root. Specifically, it aggregates two snarks at `max_depth - 1` and then computes the keccaks to get the final merkle mountain root.
#[derive(Clone)]
pub struct EthBlockHeaderChainFinalAggregationCircuit(pub EthBlockHeaderChainAggregationCircuit);

impl EthBlockHeaderChainFinalAggregationCircuit {
    /// `snarks` should be exactly two snarks of either
    /// - `EthBlockHeaderChainCircuit` if `max_depth == initial_depth + 1` or
    /// - `EthBlockHeaderChainAggregationCircuit` otherwise
    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks: Vec<Snark>,
        snark_instances: [EthBlockHeaderChainInstance; 2],
        transcript: &mut PoseidonTranscript<NativeLoader, Vec<u8>>,
        rng: &mut (impl Rng + Send),
        num_blocks: u32,
        max_depth: usize,
        initial_depth: usize,
    ) -> Self {
        let mut pre_circuit = EthBlockHeaderChainAggregationCircuit::new(
            params,
            snarks,
            snark_instances,
            transcript,
            rng,
            num_blocks,
            max_depth,
            initial_depth,
        );
        let leaves = &pre_circuit.chain_instance.merkle_mountain_range
            [..num_blocks as usize >> initial_depth];
        let mut new_mmr = get_merkle_mountain_range(leaves, max_depth - initial_depth);
        new_mmr.extend_from_slice(
            &pre_circuit.chain_instance.merkle_mountain_range[1 << (max_depth - initial_depth)..],
        );
        pre_circuit.chain_instance.merkle_mountain_range = new_mmr;
        Self(pre_circuit)
    }

    /// The number of instances NOT INCLUDING the accumulator
    pub fn get_num_instance(max_depth: usize) -> usize {
        5 + 2 * (max_depth + 1)
    }

    pub fn instance(&self) -> Vec<Fr> {
        [&self.0.aggregation.instances()[0], &self.0.chain_instance.to_instance()[..]].concat()
    }
}

impl Circuit<Fr> for EthBlockHeaderChainFinalAggregationCircuit {
    type Config = AggregationWithKeccakConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self(self.0.without_witnesses())
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let params = AggregationWithKeccakConfigParams::get();
        AggregationWithKeccakConfig::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: AggregationWithKeccakConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        #[cfg(feature = "display")]
        let witness_time = start_timer!(|| format!(
            "synthesize {:6x}-{:6x} {} {} with keccak",
            self.0.chain_instance.start_block_number,
            self.0.chain_instance.end_block_number,
            self.0.max_depth,
            self.0.initial_depth
        ));
        config.range().load_lookup_table(&mut layouter).expect("load range lookup table");
        config.keccak.load_aux_tables(&mut layouter).expect("load keccak lookup table");
        let gamma = layouter.get_challenge(config.rlc.gamma);
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        let mut instances = Vec::new();
        layouter
            .assign_region(
                || "Block header chain final aggregation circuit",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let (mut pre_instances, num_blocks_minus_one, loader) =
                        self.0.aggregate_and_join_instances(&config.aggregation, region);
                    let ctx = &mut loader.ctx_mut();
                    // add RLC context
                    ctx.advice_alloc.push((0, 0));

                    // compute the keccaks that were delayed, to get the `max_depth - initial_depth + 1` biggest merkle mountain ranges
                    let num_blocks = config.gate().add(
                        ctx,
                        Existing(&num_blocks_minus_one),
                        Constant(Fr::one()),
                    );
                    let bits = config.gate().num_to_bits(ctx, &num_blocks, self.0.max_depth + 1);
                    // bits is in little endian, we take the top `max_depth - initial_depth + 1` bits
                    let num_leaves = 1 << (self.0.max_depth - self.0.initial_depth);
                    let num_leaves_bits = &bits[self.0.initial_depth..];
                    let start_idx = 4 * LIMBS + 5;
                    // convert from u128 to bytes
                    let leaves = &pre_instances[start_idx..]
                        .chunks(2)
                        .take(num_leaves)
                        .map(|hash| {
                            hash.iter()
                                .flat_map(|hash_u128| {
                                    num_to_bytes_be(
                                        ctx,
                                        config.range(),
                                        hash_u128,
                                        NUM_BYTES_IN_U128,
                                    )
                                })
                                .collect_vec()
                        })
                        .collect_vec();

                    let mut rlc_chip = RlcChip::new(config.rlc.clone(), gamma);
                    let mut keccak_chip = KeccakChip::new(config.keccak.clone());
                    let new_mmr = keccak_chip.merkle_mountain_range(
                        ctx,
                        config.gate(),
                        leaves,
                        num_leaves_bits,
                    );
                    let new_mmr_len = new_mmr.len();
                    debug_assert_eq!(new_mmr_len, self.0.max_depth - self.0.initial_depth + 1);
                    // convert from bytes to u128
                    for ((pair, hash_bytes), bit) in pre_instances[start_idx..]
                        .chunks_mut(2)
                        .zip(new_mmr.iter())
                        .zip(num_leaves_bits.iter().rev())
                    {
                        let hash_u128s = bytes_be_to_u128(ctx, config.gate(), &hash_bytes[..]);
                        debug_assert_eq!(hash_u128s.len(), 2);
                        for (instance, hash_u128) in pair.iter_mut().zip(hash_u128s.into_iter()) {
                            *instance = config.gate().mul(ctx, Existing(&hash_u128), Existing(bit));
                        }
                    }
                    // TODO: maybe `copy_within` is better, after `AssignedValue` derives `Copy`?
                    drop(
                        pre_instances
                            .drain(start_idx + 2 * new_mmr_len..start_idx + 2 * num_leaves),
                    );
                    instances.extend(pre_instances.iter().map(|assigned| assigned.cell()).cloned());
                    keccak_chip.assign_phase0(&mut ctx.region);
                    config.range().finalize(ctx);
                    ctx.next_phase();

                    // ============ SECOND PHASE ============
                    rlc_chip.get_challenge(ctx);
                    let (fixed_len_rlcs, var_len_rlcs) =
                        keccak_chip.compute_all_rlcs(ctx, &mut rlc_chip, config.gate());
                    keccak_chip.assign_phase1(
                        ctx,
                        config.range(),
                        rlc_chip.gamma,
                        &fixed_len_rlcs,
                        &var_len_rlcs,
                    );
                    config.range().finalize(ctx);

                    #[cfg(feature = "display")]
                    {
                        ctx.print_stats(&["Range", "RLC"]);
                    }
                    Ok(())
                },
            )
            .unwrap();

        for (i, cell) in instances.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.aggregation.instance, i);
        }
        #[cfg(feature = "display")]
        end_timer!(witness_time);
        Ok(())
    }
}

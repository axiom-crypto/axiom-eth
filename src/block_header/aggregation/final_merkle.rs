use crate::{
    block_header::aggregation::join_previous_instances,
    keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs},
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        RlpChip,
    },
    util::{
        bytes_be_to_u128, get_merkle_mountain_range, num_to_bytes_be, EthConfigParams,
        NUM_BYTES_IN_U128,
    },
    EthCircuitBuilder,
};
#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::{builder::CircuitBuilderStage, GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr},
        poly::kzg::commitment::ParamsKZG,
    },
    QuantumCell::Constant,
};
use snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, Snark, SHPLONK};
use std::{cell::RefCell, env::var};

use super::EthBlockHeaderChainAggregationCircuit;

/// Same as `EthBlockHeaderChainAggregationCircuit` but uses Keccak chip to compute the final merkle mountain root. Specifically, it aggregates two snarks at `max_depth - 1` and then computes the keccaks to get the final merkle mountain root.
#[derive(Clone, Debug)]
pub struct EthBlockHeaderChainFinalAggregationCircuit(pub EthBlockHeaderChainAggregationCircuit);

impl EthBlockHeaderChainFinalAggregationCircuit {
    pub fn new(
        snarks: Vec<Snark>,
        num_blocks: u32,
        max_depth: usize,
        initial_depth: usize,
    ) -> Self {
        let mut inner = EthBlockHeaderChainAggregationCircuit::new(
            snarks,
            num_blocks,
            max_depth,
            initial_depth,
        );
        #[cfg(debug_assertions)]
        {
            let leaves =
                &inner.chain_instance.merkle_mountain_range[..num_blocks as usize >> initial_depth];
            let mut new_mmr = get_merkle_mountain_range(leaves, max_depth - initial_depth);
            new_mmr.extend_from_slice(
                &inner.chain_instance.merkle_mountain_range[1 << (max_depth - initial_depth)..],
            );
            inner.chain_instance.merkle_mountain_range = new_mmr;
        }
        Self(inner)
    }

    /// `snarks` should be exactly two snarks of either
    /// - `EthBlockHeaderChainCircuit` if `max_depth == initial_depth + 1` or
    /// - `EthBlockHeaderChainAggregationCircuit` otherwise
    pub fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<RlcThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let num_blocks = self.0.num_blocks;
        let max_depth = self.0.max_depth;
        let initial_depth = self.0.initial_depth;
        #[cfg(feature = "display")]
        let timer = start_timer!(|| {
            format!("New EthBlockHeaderChainFinalAggregationCircuit | num_blocks: {num_blocks} | max_depth: {max_depth} | initial_depth: {initial_depth}")
        });
        let aggregation = AggregationCircuit::new::<SHPLONK>(
            stage,
            Some(Vec::new()), // break points aren't actually used, since we will just take the builder from this circuit
            lookup_bits,
            params,
            self.0.snarks,
        );
        // All computations are contained in the `aggregations`'s builder, so we take that to create a new RlcThreadBuilder
        let mut builder = RlcThreadBuilder {
            threads_rlc: Vec::new(),
            gate_builder: aggregation.inner.circuit.0.builder.take(),
        };
        // TODO: should reuse RangeChip from aggregation circuit, but can't refactor right now
        let range = RangeChip::<Fr>::default(lookup_bits);
        let ctx = builder.gate_builder.main(0);
        let num_blocks_minus_one =
            ctx.load_witness(range.gate().get_field_element(num_blocks as u64 - 1));
        let new_instances = join_previous_instances(
            ctx,
            &range,
            aggregation.previous_instances.try_into().unwrap(),
            num_blocks_minus_one,
            max_depth,
            initial_depth,
        );
        let num_blocks = range.gate().add(ctx, num_blocks_minus_one, Constant(Fr::one()));

        // compute the keccaks that were delayed, to get the `max_depth - initial_depth + 1` biggest merkle mountain ranges
        let mut keccak = KeccakChip::default();
        let bits = range.gate().num_to_bits(ctx, num_blocks, max_depth + 1);
        // bits is in little endian, we take the top `max_depth - initial_depth + 1` bits
        let num_leaves = 1 << (max_depth - initial_depth);
        let num_leaves_bits = &bits[initial_depth..];
        let mmr_instances = &new_instances[5..];
        // convert from u128 to bytes
        let leaves: Vec<_> = mmr_instances
            .chunks(2)
            .take(num_leaves)
            .map(|hash| -> Vec<_> {
                hash.iter()
                    .flat_map(|hash_u128| {
                        num_to_bytes_be(ctx, &range, hash_u128, NUM_BYTES_IN_U128)
                    })
                    .collect()
            })
            .collect();
        let new_mmr = keccak.merkle_mountain_range(ctx, range.gate(), &leaves, num_leaves_bits);
        let new_mmr_len = new_mmr.len();
        debug_assert_eq!(new_mmr_len, max_depth - initial_depth + 1);
        // convert from bytes to u128
        let new_mmr =
            new_mmr.into_iter().zip(num_leaves_bits.iter().rev()).flat_map(|(hash_bytes, bit)| {
                let hash_u128s: [_; 2] =
                    bytes_be_to_u128(ctx, range.gate(), &hash_bytes[..]).try_into().unwrap();
                hash_u128s.map(|hash_u128| range.gate().mul(ctx, hash_u128, *bit))
            });
        let mut assigned_instances = aggregation.inner.assigned_instances;
        assigned_instances.extend_from_slice(&new_instances[..5]);
        assigned_instances.extend(new_mmr);
        assigned_instances.extend_from_slice(&mmr_instances[2 * num_leaves..]);

        let prover = builder.witness_gen_only();
        let circuit = EthCircuitBuilder::new(
            assigned_instances,
            builder,
            RefCell::new(keccak),
            range,
            break_points,
            |_: &mut RlcThreadBuilder<Fr>,
             _: RlpChip<Fr>,
             _: (FixedLenRLCs<Fr>, VarLenRLCs<Fr>)| {},
        );
        #[cfg(feature = "display")]
        end_timer!(timer);
        #[cfg(not(feature = "production"))]
        if !prover {
            let config_params: EthConfigParams = serde_json::from_str(
                var("ETH_CONFIG_PARAMS").expect("ETH_CONFIG_PARAMS is not set").as_str(),
            )
            .unwrap();
            circuit.config(config_params.degree as usize, Some(config_params.unusable_rows));
        }
        circuit
    }

    /// The number of instances NOT INCLUDING the accumulator
    pub fn get_num_instance(max_depth: usize) -> usize {
        5 + 2 * (max_depth + 1)
    }
}

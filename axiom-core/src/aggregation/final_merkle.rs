//! The root of the aggregation tree.
//! An [EthBlockHeaderChainRootAggregationCircuit] can aggregate either:
//! - two [crate::header_chain::EthBlockHeaderChainCircuit]s (if `max_depth == initial_depth + 1`) or
//! - two [super::intermediate::EthBlockHeaderChainIntermediateAggregationCircuit]s.
//!
//! The difference between Intermediate and Root aggregation circuits is that the Intermediate ones
//! do not have a keccak sub-circuit: all keccaks are delayed until the Root aggregation.
use std::iter;

use anyhow::{bail, Result};
use axiom_eth::{
    halo2_base::{
        gates::{GateInstructions, RangeInstructions},
        QuantumCell::Constant,
    },
    halo2_proofs::poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    halo2curves::bn256::{Bn256, Fr},
    mpt::MPTChip,
    rlc::circuit::builder::RlcCircuitBuilder,
    snark_verifier_sdk::halo2::aggregation::{
        aggregate_snarks, SnarkAggregationOutput, Svk, VerifierUniversality,
    },
    snark_verifier_sdk::{Snark, SHPLONK},
    utils::{
        build_utils::aggregation::CircuitMetadata,
        eth_circuit::EthCircuitInstructions,
        keccak::decorator::RlcKeccakCircuitImpl,
        snark_verifier::{get_accumulator_indices, NUM_FE_ACCUMULATOR},
        uint_to_bytes_be,
    },
};
use itertools::Itertools;

use super::intermediate::{
    join_previous_instances, EthBlockHeaderChainIntermediateAggregationInput,
};

/// Same as [super::intermediate::EthBlockHeaderChainIntermediateAggregationCircuit] but uses a Keccak sub-circuit to compute the final merkle mountain range. Specifically, it aggregates two snarks at `max_depth - 1` and then computes the keccaks to get the final merkle mountain root.
pub type EthBlockHeaderChainRootAggregationCircuit =
    RlcKeccakCircuitImpl<Fr, EthBlockHeaderChainRootAggregationInput>;

/// The input needed to construct [EthBlockHeaderChainRootAggregationCircuit]
#[derive(Clone, Debug)]
pub struct EthBlockHeaderChainRootAggregationInput {
    /// See [EthBlockHeaderChainIntermediateAggregationInput]
    pub inner: EthBlockHeaderChainIntermediateAggregationInput,
    /// Succinct verifying key (generator of KZG trusted setup) should match `inner.snarks`
    pub svk: Svk,
    prev_acc_indices: Vec<Vec<usize>>,
}

impl EthBlockHeaderChainRootAggregationInput {
    /// `snarks` should be exactly two snarks of either
    /// - `EthBlockHeaderChainCircuit` if `max_depth == initial_depth + 1` or
    /// - `EthBlockHeaderChainIntermediateAggregationCircuit` otherwise
    ///
    /// We only need the generator `kzg_params.get_g()[0]` to match that of the trusted setup used
    /// in the creation of `snarks`.
    pub fn new(
        snarks: Vec<Snark>,
        num_blocks: u32,
        max_depth: usize,
        initial_depth: usize,
        kzg_params: &ParamsKZG<Bn256>,
    ) -> Result<Self> {
        let svk = kzg_params.get_g()[0].into();
        let prev_acc_indices = get_accumulator_indices(&snarks);
        if max_depth == initial_depth + 1
            && prev_acc_indices.iter().any(|indices| !indices.is_empty())
        {
            bail!("Snarks to be aggregated must not have accumulators: they should come from EthBlockHeaderChainCircuit");
        }
        if max_depth > initial_depth + 1
            && prev_acc_indices.iter().any(|indices| indices.len() != NUM_FE_ACCUMULATOR)
        {
            bail!("Snarks to be aggregated must all be EthBlockHeaderChainIntermediateAggregationCircuits");
        }
        let inner = EthBlockHeaderChainIntermediateAggregationInput::new(
            snarks,
            num_blocks,
            max_depth,
            initial_depth,
        );
        Ok(Self { inner, svk, prev_acc_indices })
    }
}

impl EthCircuitInstructions<Fr> for EthBlockHeaderChainRootAggregationInput {
    type FirstPhasePayload = ();

    fn virtual_assign_phase0(&self, builder: &mut RlcCircuitBuilder<Fr>, mpt: &MPTChip<Fr>) {
        let EthBlockHeaderChainIntermediateAggregationInput {
            max_depth,
            initial_depth,
            num_blocks,
            snarks,
        } = self.inner.clone();

        let keccak = mpt.keccak();
        let range = keccak.range();
        let pool = builder.base.pool(0);
        let SnarkAggregationOutput { mut previous_instances, accumulator, .. } =
            aggregate_snarks::<SHPLONK>(pool, range, self.svk, snarks, VerifierUniversality::None);
        // remove old accumulators
        for (prev_instance, acc_indices) in
            previous_instances.iter_mut().zip_eq(&self.prev_acc_indices)
        {
            for i in acc_indices.iter().sorted().rev() {
                prev_instance.remove(*i);
            }
        }

        let ctx = pool.main();
        let num_blocks_minus_one = ctx.load_witness(Fr::from(num_blocks as u64 - 1));
        let new_instances = join_previous_instances(
            ctx,
            range,
            previous_instances.try_into().unwrap(),
            num_blocks_minus_one,
            max_depth,
            initial_depth,
        );
        let num_blocks = range.gate().add(ctx, num_blocks_minus_one, Constant(Fr::one()));

        // compute the keccaks that were delayed, to get the `max_depth - initial_depth + 1` biggest merkle mountain ranges
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
                        uint_to_bytes_be(ctx, range, hash_u128, 16).into_iter().map(|x| x.into())
                    })
                    .collect()
            })
            .collect();
        let new_mmr = keccak.merkle_mountain_range(ctx, &leaves, num_leaves_bits);
        let new_mmr_len = new_mmr.len();
        debug_assert_eq!(new_mmr_len, max_depth - initial_depth + 1);
        // convert from bytes to u128
        let new_mmr = new_mmr
            .into_iter()
            .zip(num_leaves_bits.iter().rev())
            .flat_map(|((_hash_bytes, hash_u128s), bit)| {
                // hash_u128s is in hi-lo form
                hash_u128s.map(|hash_u128| range.gate().mul(ctx, hash_u128, *bit))
            })
            .collect_vec();

        // expose public instances
        let assigned_instances = builder.public_instances();
        assert_eq!(assigned_instances.len(), 1);
        assigned_instances[0].extend(
            iter::empty()
                .chain(accumulator)
                .chain(new_instances[..5].to_vec())
                .chain(new_mmr)
                .chain(mmr_instances[2 * num_leaves..].to_vec()),
        );
    }

    fn virtual_assign_phase1(
        &self,
        _: &mut RlcCircuitBuilder<Fr>,
        _: &MPTChip<Fr>,
        _: Self::FirstPhasePayload,
    ) {
        // do nothing
    }
}

impl CircuitMetadata for EthBlockHeaderChainRootAggregationInput {
    const HAS_ACCUMULATOR: bool = true;
    /// The instance format exactly matches that of `EthBlockHeaderChainInput`.
    fn num_instance(&self) -> Vec<usize> {
        vec![NUM_FE_ACCUMULATOR + 2 + 2 + 1 + 2 * (self.inner.max_depth + 1)]
    }
}

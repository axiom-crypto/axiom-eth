//! Aggregation circuits involving only Poseidon hashes, used for aggregation of
//! `RowConsistencyCircuit` and `VerifyVsMmrCircuit`.

use halo2_base::{
    gates::{
        builder::{CircuitBuilderStage, MultiPhaseThreadBreakPoints},
        GateChip,
    },
    halo2_proofs::{
        halo2curves::bn256::{Bn256, G1Affine},
        poly::kzg::commitment::ParamsKZG,
    },
};
use itertools::Itertools;
use snark_verifier::{loader::halo2::Halo2Loader, util::hash::Poseidon};
use snark_verifier_sdk::{
    halo2::{aggregation::AggregationCircuit, POSEIDON_SPEC},
    Snark, LIMBS,
};

use crate::{
    batch_query::{
        hash::{poseidon_onion, poseidon_tree_root},
        DummyEccChip,
    },
    rlp::rlc::FIRST_PHASE,
    util::circuit::PublicAggregationCircuit,
    AggregationPreCircuit,
};

use super::HashStrategy;

/// Aggregates snarks and computes *possibly multiple* Poseidon Merkle roots of previous public instances.
///
/// See [`PublicAggregationCircuit`] for `snarks` format.
///
/// Assumes public instances of previous `snarks`, excluding old accumulators, come in tuples of `num_roots` field elements.
///
/// The circuit concatenates all previous public instances, aside from old accumulators, into `instance` and computes `num_roots` Poseidon Merkle roots.
/// * `i`th Poseidon Merkle root is computed from `instance[j * num_roots + i]` for all `j`
///
/// Public instances of the circuit are the accumulators, followed by:
/// * `num_roots` Poseidon roots (each a single field element)
//
// This is same as `MerkleAggregationCircuit`, but with empty `keccak_indices`. This means we don't need `KeccakChip`.
#[derive(Clone, Debug)]
pub struct PoseidonAggregationCircuit {
    pub strategy: HashStrategy,
    pub snarks: Vec<(Snark, bool)>,
    pub num_roots: usize,
}

impl PoseidonAggregationCircuit {
    pub fn new(strategy: HashStrategy, snarks: Vec<(Snark, bool)>, num_roots: usize) -> Self {
        assert!(!snarks.is_empty(), "no snarks to aggregate");
        let mut total_instances = 0;
        for (snark, has_acc) in &snarks {
            let start = (*has_acc as usize) * 4 * LIMBS;
            let n = snark.instances.iter().map(|x| x.len()).sum::<usize>() - start;
            assert_eq!(n % num_roots, 0, "snark does not have correct number of instances");
            total_instances += n;
        }
        let num_leaves = total_instances / num_roots;
        assert!(num_leaves > 0, "no leaves to merklelize");
        Self { strategy, snarks, num_roots }
    }
}

impl AggregationPreCircuit for PoseidonAggregationCircuit {
    fn create(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
    ) -> AggregationCircuit {
        log::info!(
            "New PoseidonAggregationCircuit | num_snarks: {} | num_roots: {}",
            self.snarks.len(),
            self.num_roots
        );
        // aggregate the snarks
        let mut aggregation = PublicAggregationCircuit::new(self.snarks).private(
            stage,
            break_points,
            lookup_bits,
            params,
        );
        let previous_instances = &aggregation.previous_instances;

        let builder = aggregation.inner.circuit.0.builder.take();
        // TODO: should reuse GateChip from aggregation circuit, but can't refactor right now
        let gate = GateChip::default();
        let _chip = DummyEccChip(&gate);
        let loader = Halo2Loader::<G1Affine, _>::new(_chip, builder);
        // load field elements from prev instances to Scalar
        let mut poseidon_leaves = vec![vec![]; self.num_roots];
        for prev_instance in previous_instances {
            for hashes in prev_instance.chunks_exact(self.num_roots) {
                for (hash, poseidon_leaves) in hashes.iter().zip_eq(poseidon_leaves.iter_mut()) {
                    poseidon_leaves.push(loader.scalar_from_assigned(*hash));
                }
            }
        }
        let mut poseidon = Poseidon::from_spec(&loader, POSEIDON_SPEC.clone());
        let poseidon_roots = poseidon_leaves
            .into_iter()
            .map(|leaves| match self.strategy {
                HashStrategy::Tree => {
                    poseidon_tree_root(&mut poseidon, leaves, &[]).into_assigned()
                }
                HashStrategy::Onion => {
                    poseidon_onion(&mut poseidon, leaves.into_iter().map(|leaf| leaf.into()))
                        .into_assigned()
                }
            })
            .collect_vec();
        // put builder back
        aggregation.inner.circuit.0.builder.replace(loader.take_ctx());
        // add new public instances
        aggregation.inner.assigned_instances.extend(poseidon_roots);

        aggregation
    }
}

// Special circuit, not worth generalizing to avoid confusion:

/// Special circuit just for aggregating [`crate::batch_query::response::block_header::MultiBlockCircuit`]
///
/// Assumes public instances of previous `snarks`, excluding old accumulators, have the form:
/// * ...
/// * `historical_mmr_keccak`: an H256, 2 field elements in hi-lo form
/// * `recent_mmr_keccak`: an H256, 2 field elements in hi-lo form
///
/// The circuit passes through all previous public instances, excluding accumulators **and** excluding `historical_mmr_keccak` and `recent_mmr_keccak`.
///
/// The circuit constrains that `historical_mmr_keccak[i] = historical_mmr_keccak[j]` and `recent_mmr_keccak[i] = recent_mmr_keccak[j]` for all `i, j`
///
/// Public instances of the circuit is the accumulator, followed by:
/// * ...Pass through previous instances
/// * `historical_mmr_keccak`
/// * `recent_mmr_keccak`
#[derive(Clone, Debug)]
pub struct MultiBlockAggregationCircuit {
    pub snarks: Vec<(Snark, bool)>,
}

impl MultiBlockAggregationCircuit {
    pub fn new(snarks: Vec<(Snark, bool)>) -> Self {
        Self { snarks }
    }
}

impl AggregationPreCircuit for MultiBlockAggregationCircuit {
    fn create(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
    ) -> AggregationCircuit {
        log::info!("New VerifyVsMmrAggregationCircuit | num_snarks: {}", self.snarks.len(),);
        // aggregate the snarks
        let mut aggregation = PublicAggregationCircuit::new(self.snarks).private(
            stage,
            break_points,
            lookup_bits,
            params,
        );
        let previous_instances = &aggregation.previous_instances;
        let len0 = previous_instances[0].len();

        let mut builder = aggregation.inner.circuit.0.builder.borrow_mut();
        let ctx = builder.main(FIRST_PHASE);
        for prev_instance in previous_instances.iter().skip(1) {
            let len = prev_instance.len();
            for i in 1..=4 {
                ctx.constrain_equal(&previous_instances[0][len0 - i], &prev_instance[len - i]);
            }
        }
        drop(builder);
        // add new public instances
        aggregation.inner.assigned_instances.extend(
            previous_instances
                .iter()
                .flat_map(|instance| instance[..instance.len() - 4].to_vec())
                .chain(previous_instances[0][len0 - 4..].to_vec()),
        );

        aggregation
    }
}

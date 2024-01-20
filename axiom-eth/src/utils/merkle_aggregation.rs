use std::iter;

use anyhow::{bail, Result};
use itertools::Itertools;

use crate::{
    halo2_base::{
        gates::{circuit::CircuitBuilderStage, GateChip},
        poseidon::hasher::PoseidonHasher,
    },
    halo2_proofs::poly::kzg::commitment::ParamsKZG,
    halo2curves::bn256::Bn256,
    snark_verifier_sdk::{
        halo2::{
            aggregation::{AggregationCircuit, VerifierUniversality},
            POSEIDON_SPEC,
        },
        SHPLONK,
    },
    utils::{
        build_utils::pinning::aggregation::AggregationCircuitPinning,
        component::utils::compute_poseidon_merkle_tree,
    },
};

use super::snark_verifier::{
    get_accumulator_indices, AggregationCircuitParams, EnhancedSnark, NUM_FE_ACCUMULATOR,
};

/// The input to the Merkle Aggregation Circuit is a collection of [EnhancedSnark]s.
/// The number of snarks does not need to be a power of two.
///
/// The `snarks` are not allowed to be from universal aggregation circuits.
///
/// We allow snarks to have accumulators (so they can be non-universal aggregation circuits).
///
/// We check that:
/// - All snarks have the same number of instances _excluding accumulators_.
/// - All snarks must have at least one non-accumulator instance.
///
/// The public instances of the Merkle Aggregation Circuit are:
/// - accumulator
/// - padded merkle root of `output`s of `snarks`, where merkle tree is padded with `0`s to next power of two. The `output` is defined as the first non-accumulator instance in each snark.
/// - `snark[i].instance[j] = snark[k].instance[j]` for all `i,j` pairs and all `j > 0`, where `snark[i].instance` are all the non-accumulator instances in `snark[i]`.
///
/// `snarks` should be non-empty.
#[derive(Clone, Debug)]
pub struct InputMerkleAggregation {
    pub snarks: Vec<EnhancedSnark>,
}

impl InputMerkleAggregation {
    /// See [InputMerkleAggregation] for details.
    pub fn new(snarks: impl IntoIterator<Item = EnhancedSnark>) -> Self {
        let snarks = snarks.into_iter().collect_vec();
        assert!(!snarks.is_empty());
        assert!(
            snarks.iter().all(|s| s.agg_vk_hash_idx.is_none()),
            "[MerkleAggregation] snark cannot be universal aggregation circuit"
        );
        Self { snarks }
    }
}

impl TryFrom<Vec<EnhancedSnark>> for InputMerkleAggregation {
    type Error = anyhow::Error;
    fn try_from(snarks: Vec<EnhancedSnark>) -> Result<Self, Self::Error> {
        if snarks.is_empty() {
            bail!("snarks cannot be empty");
        }
        if snarks.iter().all(|s| s.agg_vk_hash_idx.is_none()) {
            bail!("snark cannot be universal aggregation circuit");
        }
        Ok(Self { snarks })
    }
}

impl InputMerkleAggregation {
    /// Returns [AggregationCircuit] with loaded witnesses for a **non-universal** aggregation
    /// of the snarks in `self`.
    ///
    /// This circuit MUST implement `CircuitExt` with accumulator indices non-empty.
    ///
    /// We allow snarks to have accumulators (so they can be non-universal aggregation circuits).
    ///
    /// We will check that either:
    /// - All snarks have a single instance besides any accumulators, in which case this is the `output` of that snark
    /// - Or all snarks have 2 instances besides any accumulators, in which case this is the `(output, promise)` of that snark
    ///
    /// The public instances of the Merkle Aggregation Circuit are:
    /// - accumulator
    /// - padded merkle root of `output`s of `snarks`, where merkle tree is padded with `0`s to next power of two
    /// - `promise` from `snark[0]` if all snarks have 2 instances. The circuit will constrain that `promise[i] == promise[j]` for all `i,j`
    ///
    /// `snarks` should be non-empty.
    pub fn build(
        self,
        stage: CircuitBuilderStage,
        circuit_params: AggregationCircuitParams,
        kzg_params: &ParamsKZG<Bn256>,
    ) -> anyhow::Result<AggregationCircuit> {
        let snarks = self.snarks;
        assert!(!snarks.is_empty());
        let prev_acc_indices = get_accumulator_indices(snarks.iter().map(|s| &s.inner));

        let mut circuit = AggregationCircuit::new::<SHPLONK>(
            stage,
            circuit_params,
            kzg_params,
            snarks.into_iter().map(|s| s.inner),
            VerifierUniversality::None,
        );

        // remove accumulator from previous instances
        let mut prev_instances = circuit.previous_instances().clone();
        for (prev_instance, acc_indices) in prev_instances.iter_mut().zip_eq(prev_acc_indices) {
            for i in acc_indices.iter().rev() {
                prev_instance.remove(*i);
            }
        }
        // number of non-accumulator instances per-snark
        let num_instance = prev_instances[0].len();
        if num_instance == 0 {
            bail!("snark should have at least 1 instances");
        }
        if prev_instances.iter().any(|i| i.len() != num_instance) {
            bail!("snarks should have same number of instances");
        }
        let builder = &mut circuit.builder;
        let ctx = builder.main(0);
        let const_zero = ctx.load_zero();
        // Compute Merkle root of instance[0] over all snarks
        let num_leaves = prev_instances.len().next_power_of_two();
        let leaves = prev_instances
            .iter()
            .map(|instance| instance[0])
            .chain(iter::repeat(const_zero))
            .take(num_leaves)
            .collect_vec();

        // Optimization: if there is only one snark, we don't need to compute the merkle tree so no need to create hasher.
        let merkle_root = if leaves.len() == 1 {
            leaves[0]
        } else {
            let mut hasher = PoseidonHasher::new(POSEIDON_SPEC.clone());
            let gate = GateChip::default();
            hasher.initialize_consts(ctx, &gate);
            let nodes = compute_poseidon_merkle_tree(ctx, &gate, &hasher, leaves);
            nodes[0]
        };

        // If instance[1] exists, constrain that instance[1] is equal for all snarks
        for j in 1..num_instance {
            let instance_0j = &prev_instances[0][j];
            for instance in prev_instances.iter().skip(1) {
                ctx.constrain_equal(instance_0j, &instance[j]);
            }
        }

        if builder.assigned_instances.len() != 1 {
            bail!("should only have 1 instance column");
        }
        assert_eq!(builder.assigned_instances[0].len(), NUM_FE_ACCUMULATOR);
        builder.assigned_instances[0].push(merkle_root);
        builder.assigned_instances[0].extend_from_slice(&prev_instances[0][1..]);

        Ok(circuit)
    }

    /// Circuit for witness generation only
    pub fn prover_circuit(
        self,
        pinning: AggregationCircuitPinning,
        kzg_params: &ParamsKZG<Bn256>,
    ) -> Result<AggregationCircuit> {
        Ok(self
            .build(CircuitBuilderStage::Prover, pinning.params, kzg_params)?
            .use_break_points(pinning.break_points))
    }
}

#[cfg(feature = "keygen")]
/// Module only used for keygen helper utilities
pub mod keygen {
    use std::sync::Arc;

    use halo2_base::{
        gates::circuit::CircuitBuilderStage,
        halo2_proofs::{
            halo2curves::bn256::Bn256,
            poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
        },
        utils::halo2::KeygenCircuitIntent,
    };
    use snark_verifier_sdk::{
        halo2::{
            aggregation::AggregationCircuit,
            utils::{
                AggregationDependencyIntent, AggregationDependencyIntentOwned,
                KeygenAggregationCircuitIntent,
            },
        },
        CircuitExt, Snark,
    };

    use crate::{
        halo2curves::bn256::Fr,
        utils::{
            build_utils::{
                aggregation::get_dummy_aggregation_params,
                keygen::compile_agg_dep_to_protocol,
                pinning::{
                    aggregation::{AggTreeId, GenericAggParams, GenericAggPinning},
                    CircuitPinningInstructions,
                },
            },
            snark_verifier::EnhancedSnark,
        },
    };

    use super::InputMerkleAggregation;

    /// Intent for Merkle Aggregation Circuit.
    /// For now we do not record the generator of the trusted setup here since it
    /// is assumed to be read from file.
    #[derive(Clone, Debug)]
    pub struct AggIntentMerkle {
        /// This is from bad UX; only svk = kzg_params.get_g()[0] is used
        pub kzg_params: Arc<ParamsKZG<Bn256>>,
        /// Must be same length as `deps`. Has the corresponding circuit IDs for each dependency snark
        pub to_agg: Vec<AggTreeId>,
        /// Vec of `vk, num_instance, is_aggregation` for each dependency snark
        pub deps: Vec<AggregationDependencyIntentOwned>,
        /// The log_2 domain size of the current aggregation circuit
        pub k: u32,
    }

    impl KeygenAggregationCircuitIntent for AggIntentMerkle {
        fn intent_of_dependencies(&self) -> Vec<AggregationDependencyIntent> {
            self.deps.iter().map(|d| d.into()).collect()
        }
        fn build_keygen_circuit_from_snarks(self, snarks: Vec<Snark>) -> Self::AggregationCircuit {
            let input = InputMerkleAggregation::new(
                snarks.into_iter().map(|s| EnhancedSnark::new(s, None)),
            );
            let agg_params = get_dummy_aggregation_params(self.k as usize);
            let mut circuit =
                input.build(CircuitBuilderStage::Keygen, agg_params, &self.kzg_params).unwrap();
            circuit.calculate_params(Some(20));
            circuit
        }
    }

    impl KeygenCircuitIntent<Fr> for AggIntentMerkle {
        type ConcreteCircuit = AggregationCircuit;
        /// We omit here tags (e.g., hash of vkeys) of the dependencies, they should be recorded separately.
        type Pinning = GenericAggPinning<GenericAggParams>;
        fn get_k(&self) -> u32 {
            self.k
        }
        fn build_keygen_circuit(self) -> Self::ConcreteCircuit {
            self.build_keygen_circuit_shplonk()
        }
        fn get_pinning_after_keygen(
            self,
            kzg_params: &ParamsKZG<Bn256>,
            circuit: &Self::ConcreteCircuit,
        ) -> Self::Pinning {
            let svk = kzg_params.get_g()[0];
            let dk = (svk, kzg_params.g2(), kzg_params.s_g2());
            assert_eq!(self.kzg_params.get_g()[0], svk);
            assert_eq!(self.kzg_params.g2(), dk.1);
            assert_eq!(self.kzg_params.s_g2(), dk.2);
            let pinning = circuit.pinning();
            let to_agg = self
                .deps
                .iter()
                .map(|d| compile_agg_dep_to_protocol(kzg_params, d, false))
                .collect();
            let agg_params = GenericAggParams { to_agg, agg_params: pinning.params };
            GenericAggPinning {
                params: agg_params,
                num_instance: circuit.num_instance(),
                accumulator_indices: AggregationCircuit::accumulator_indices().unwrap(),
                agg_vk_hash_data: None,
                dk: dk.into(),
                break_points: pinning.break_points,
            }
        }
    }
}

use std::{collections::BTreeMap, path::Path, sync::Arc};

use axiom_eth::{
    block_header::GENESIS_BLOCK_RLP,
    halo2_base::{
        gates::circuit::CircuitBuilderStage,
        utils::halo2::{KeygenCircuitIntent, ProvingKeyGenerator},
    },
    halo2_proofs::{
        plonk::{Circuit, ProvingKey},
        poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    },
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    snark_verifier_sdk::{
        halo2::{
            aggregation::AggregationCircuit,
            utils::{
                AggregationDependencyIntent, AggregationDependencyIntentOwned,
                KeygenAggregationCircuitIntent,
            },
        },
        CircuitExt, Snark,
    },
    utils::{
        build_utils::{
            aggregation::get_dummy_aggregation_params,
            keygen::{
                compile_agg_dep_to_protocol, get_dummy_rlc_keccak_params, read_srs_from_dir,
                write_pk_and_pinning,
            },
            pinning::aggregation::{AggTreeId, GenericAggParams, GenericAggPinning},
        },
        merkle_aggregation::keygen::AggIntentMerkle,
        DEFAULT_RLC_CACHE_BITS,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    aggregation::{
        final_merkle::{
            EthBlockHeaderChainRootAggregationCircuit, EthBlockHeaderChainRootAggregationInput,
        },
        intermediate::EthBlockHeaderChainIntermediateAggregationInput,
    },
    header_chain::{EthBlockHeaderChainCircuit, EthBlockHeaderChainInput},
    types::{
        CoreNodeParams, CoreNodeType, CorePinningIntermediate, CorePinningLeaf, CorePinningRoot,
    },
};

/// Recursive intent for a node in the aggregation tree that can construct proving keys for this node and all its children.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecursiveCoreIntent {
    /// `k_at_depth[i]` is the log2 domain size at depth `i`. So it starts from the current node and goes down the
    /// layers of the tree. Our aggregation structure is such that each layer of the tree only has a single circuit type so only one `k` is needed.
    pub k_at_depth: Vec<u32>,
    /// Different chains (e.g., Goerli) can have different maximum number of bytes in the extra data field of the block header.
    /// We configure the circuits differently based on this.
    pub max_extra_data_bytes: usize,
    pub params: CoreNodeParams,
}

impl RecursiveCoreIntent {
    pub fn new(k_at_depth: Vec<u32>, max_extra_data_bytes: usize, params: CoreNodeParams) -> Self {
        Self { k_at_depth, max_extra_data_bytes, params }
    }
    /// Each layer of tree has a unique circuit type, so this is the child circuit type.
    pub fn child(&self) -> Option<Self> {
        assert!(!self.k_at_depth.is_empty());
        self.params.child(Some(self.max_extra_data_bytes)).map(|params| Self {
            k_at_depth: self.k_at_depth[1..].to_vec(),
            max_extra_data_bytes: self.max_extra_data_bytes,
            params,
        })
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreIntentLeaf {
    pub k: u32,
    /// Different chains (e.g., Goerli) can have different maximum number of bytes in the extra data field of the block header.
    /// We configure the circuits differently based on this.
    pub max_extra_data_bytes: usize,
    /// The leaf layer of the aggregation starts with max number of block headers equal to 2<sup>depth</sup>.
    pub depth: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct CoreIntentIntermediate {
    pub k: u32,
    // This is from bad UX; only svk = kzg_params.get_g()[0] is used
    pub kzg_params: Arc<ParamsKZG<Bn256>>,
    // There will be exponential duplication since both children have the same circuit type, but it seems better for clarity
    pub to_agg: Vec<AggTreeId>,
    /// There are always two children of the same type, so we only specify the intent for one of them
    pub child_intent: AggregationDependencyIntentOwned,
    /// The maximum number of block headers in the chain at this level of the tree is 2<sup>depth</sup>.
    pub depth: usize,
    /// The leaf layer of the aggregation starts with max number of block headers equal to 2<sup>initial_depth</sup>.
    pub initial_depth: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct CoreIntentRoot {
    pub k: u32,
    // This is from bad UX; only svk = kzg_params.get_g()[0] is used
    pub(crate) kzg_params: Arc<ParamsKZG<Bn256>>,
    // There will be exponential duplication since both children have the same circuit type, but it seems better for clarity
    pub to_agg: Vec<AggTreeId>,
    /// There are always two children of the same type, so we only specify the intent for one of them
    pub child_intent: AggregationDependencyIntentOwned,
    /// The maximum number of block headers in the chain at this level of the tree is 2<sup>depth</sup>.
    pub depth: usize,
    /// The leaf layer of the aggregation starts with max number of block headers equal to 2<sup>initial_depth</sup>.
    pub initial_depth: usize,
}

/// Passthrough wrapper aggregation.
/// Internal version doesn't need any additional context.
#[derive(Clone, Debug)]
pub(crate) struct CoreIntentEvm {
    pub k: u32,
    // This is from bad UX; only svk = kzg_params.get_g()[0] is used
    pub kzg_params: Arc<ParamsKZG<Bn256>>,
    /// Tree of the single child
    pub to_agg: AggTreeId,
    /// Wrap single child
    pub child_intent: AggregationDependencyIntentOwned,
}

impl KeygenCircuitIntent<Fr> for CoreIntentLeaf {
    type ConcreteCircuit = EthBlockHeaderChainCircuit<Fr>;
    type Pinning = CorePinningLeaf;
    fn get_k(&self) -> u32 {
        self.k
    }
    fn build_keygen_circuit(self) -> Self::ConcreteCircuit {
        let dummy_input = EthBlockHeaderChainInput::<Fr>::new(
            vec![GENESIS_BLOCK_RLP.to_vec(); 1 << self.depth], // the resizing of each header RLP is handled by constructor
            1,
            self.depth,
            self.max_extra_data_bytes,
        );
        let circuit_params = get_dummy_rlc_keccak_params(self.k as usize, 8);
        let mut circuit = EthBlockHeaderChainCircuit::new_impl(
            CircuitBuilderStage::Keygen,
            dummy_input,
            circuit_params,
            DEFAULT_RLC_CACHE_BITS,
        );
        circuit.calculate_params();
        circuit
    }
    fn get_pinning_after_keygen(
        self,
        kzg_params: &ParamsKZG<Bn256>,
        circuit: &Self::ConcreteCircuit,
    ) -> Self::Pinning {
        let params = circuit.params();
        let break_points = circuit.break_points();
        let num_instance = circuit.num_instance();
        let dk = (kzg_params.get_g()[0], kzg_params.g2(), kzg_params.s_g2());
        CorePinningLeaf { params, break_points, num_instance, dk: dk.into() }
    }
}

impl KeygenAggregationCircuitIntent for CoreIntentIntermediate {
    fn intent_of_dependencies(&self) -> Vec<AggregationDependencyIntent> {
        vec![(&self.child_intent).into(); 2]
    }
    fn build_keygen_circuit_from_snarks(self, snarks: Vec<Snark>) -> Self::AggregationCircuit {
        assert_eq!(snarks.len(), 2);

        let input = EthBlockHeaderChainIntermediateAggregationInput::new(
            snarks,
            1,
            self.depth,
            self.initial_depth,
        );
        let circuit_params = get_dummy_aggregation_params(self.k as usize);
        let mut circuit =
            input.build(CircuitBuilderStage::Keygen, circuit_params, &self.kzg_params).unwrap();
        circuit.0.calculate_params(Some(20));
        circuit.0
    }
}

impl KeygenCircuitIntent<Fr> for CoreIntentIntermediate {
    type ConcreteCircuit = AggregationCircuit;
    type Pinning = CorePinningIntermediate;
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
        let to_agg = compile_agg_dep_to_protocol(kzg_params, &self.child_intent, false);
        let dk = (kzg_params.get_g()[0], kzg_params.g2(), kzg_params.s_g2());
        CorePinningIntermediate {
            params: circuit.params(),
            to_agg: vec![to_agg; self.to_agg.len()],
            break_points: circuit.break_points(),
            num_instance: circuit.num_instance(),
            dk: dk.into(),
        }
    }
}

impl KeygenAggregationCircuitIntent for CoreIntentRoot {
    type AggregationCircuit = EthBlockHeaderChainRootAggregationCircuit;
    fn intent_of_dependencies(&self) -> Vec<AggregationDependencyIntent> {
        vec![(&self.child_intent).into(); 2]
    }
    fn build_keygen_circuit_from_snarks(self, snarks: Vec<Snark>) -> Self::AggregationCircuit {
        assert_eq!(snarks.len(), 2);

        let input = EthBlockHeaderChainRootAggregationInput::new(
            snarks,
            1,
            self.depth,
            self.initial_depth,
            &self.kzg_params,
        )
        .unwrap();
        // This is aggregation circuit, so set lookup bits to max
        let circuit_params = get_dummy_rlc_keccak_params(self.k as usize, self.k as usize - 1);
        // This is from bad UX; only svk = kzg_params.get_g()[0] is used
        let mut circuit = EthBlockHeaderChainRootAggregationCircuit::new_impl(
            CircuitBuilderStage::Keygen,
            input,
            circuit_params,
            0, // note: rlc is not used
        );
        circuit.calculate_params();
        circuit
    }
}

impl KeygenCircuitIntent<Fr> for CoreIntentRoot {
    type ConcreteCircuit = EthBlockHeaderChainRootAggregationCircuit;
    type Pinning = CorePinningRoot;
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
        let params = circuit.params();
        let break_points = circuit.break_points();
        let to_agg = compile_agg_dep_to_protocol(kzg_params, &self.child_intent, false);
        let dk = (kzg_params.get_g()[0], kzg_params.g2(), kzg_params.s_g2());
        CorePinningRoot {
            params,
            to_agg: vec![to_agg; self.to_agg.len()],
            num_instance: circuit.num_instance(),
            break_points,
            dk: dk.into(),
        }
    }
}

impl From<CoreIntentEvm> for AggIntentMerkle {
    fn from(value: CoreIntentEvm) -> Self {
        AggIntentMerkle {
            kzg_params: value.kzg_params,
            to_agg: vec![value.to_agg],
            deps: vec![value.child_intent],
            k: value.k,
        }
    }
}

impl KeygenCircuitIntent<Fr> for CoreIntentEvm {
    type ConcreteCircuit = AggregationCircuit;
    type Pinning = GenericAggPinning<GenericAggParams>;
    fn get_k(&self) -> u32 {
        self.k
    }
    fn build_keygen_circuit(self) -> Self::ConcreteCircuit {
        AggIntentMerkle::from(self).build_keygen_circuit()
    }
    fn get_pinning_after_keygen(
        self,
        kzg_params: &ParamsKZG<Bn256>,
        circuit: &Self::ConcreteCircuit,
    ) -> Self::Pinning {
        AggIntentMerkle::from(self).get_pinning_after_keygen(kzg_params, circuit)
    }
}

impl RecursiveCoreIntent {
    /// Recursively creates and serializes proving keys and pinnings.
    ///
    /// Computes `circuit_id` as the blake3 hash of the halo2 VerifyingKey written to bytes. Writes proving key to `circuit_id.pk`, verifying key to `circuit_id.vk` and pinning to `circuit_id.json` in the `data_dir` directory.
    ///
    /// Returns the `circuit_id, proving_key, pinning`.
    /// * `cid_repo` stores a mapping from the [CoreNodeParams] to the corresponding circuit ID. In an Axiom Core aggregation tree, the [CoreNodeParams] determines the node.
    /// * `PARAMS_DIR` **must** be set because the aggregation circuit creation requires reading trusted setup files (this can be removed later).
    pub fn create_and_serialize_proving_key(
        self,
        srs_dir: &Path,
        data_dir: &Path,
        cid_repo: &mut BTreeMap<CoreNodeParams, String>,
    ) -> anyhow::Result<(AggTreeId, ProvingKey<G1Affine>, serde_json::Value)> {
        // If there is child, do it first
        let child = if let Some(child_intent) = self.child() {
            let is_aggregation = !matches!(child_intent.params.node_type, CoreNodeType::Leaf(_));
            let (child_id, child_pk, child_pinning) =
                child_intent.create_and_serialize_proving_key(srs_dir, data_dir, cid_repo)?;
            let num_instance: Vec<usize> =
                serde_json::from_value(child_pinning["num_instance"].clone())?;
            // !! ** ASSERTION: all aggregation circuits in Axiom Core have accumulator in indices 0..12 ** !!
            // No aggregation circuits in Axiom Core are universal.
            let agg_intent = AggregationDependencyIntentOwned {
                vk: child_pk.get_vk().clone(),
                num_instance,
                accumulator_indices: is_aggregation
                    .then(|| AggregationCircuit::accumulator_indices().unwrap()),
                agg_vk_hash_data: None,
            };
            Some((child_id, agg_intent))
        } else {
            None
        };
        assert!(!self.k_at_depth.is_empty());
        let k = self.k_at_depth[0];
        let kzg_params = Arc::new(read_srs_from_dir(srs_dir, k)?);
        let ((pk, pinning), children) = match self.params.node_type {
            CoreNodeType::Leaf(max_extra_data_bytes) => {
                let intent =
                    CoreIntentLeaf { k, max_extra_data_bytes, depth: self.params.initial_depth };
                (intent.create_pk_and_pinning(&kzg_params), vec![])
            }
            CoreNodeType::Intermediate => {
                let (child_id, child_intent) = child.unwrap();
                let to_agg = vec![child_id; 2];
                let intent = CoreIntentIntermediate {
                    k,
                    kzg_params: kzg_params.clone(),
                    to_agg: to_agg.clone(),
                    child_intent,
                    depth: self.params.depth,
                    initial_depth: self.params.initial_depth,
                };
                (intent.create_pk_and_pinning(&kzg_params), to_agg)
            }
            CoreNodeType::Root => {
                let (child_id, child_intent) = child.unwrap();
                let to_agg = vec![child_id; 2];
                let intent = CoreIntentRoot {
                    k,
                    kzg_params: kzg_params.clone(),
                    to_agg: to_agg.clone(),
                    child_intent,
                    depth: self.params.depth,
                    initial_depth: self.params.initial_depth,
                };
                (intent.create_pk_and_pinning(&kzg_params), to_agg)
            }
            CoreNodeType::Evm(_) => {
                let (child_id, child_intent) = child.unwrap();
                let to_agg = vec![child_id.clone()];
                let intent = CoreIntentEvm {
                    k,
                    to_agg: child_id,
                    child_intent,
                    kzg_params: kzg_params.clone(),
                };
                (intent.create_pk_and_pinning(&kzg_params), to_agg)
            }
        };
        let circuit_id = write_pk_and_pinning(data_dir, &pk, &pinning)?;
        if let Some(old_cid) = cid_repo.insert(self.params, circuit_id.clone()) {
            if old_cid != circuit_id {
                anyhow::bail!("Different circuit ID for the same node params")
            }
        }
        let tree_id = AggTreeId { circuit_id, children, aggregate_vk_hash: None };
        Ok((tree_id, pk, pinning))
    }
}

use axiom_eth::{
    halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints,
    halo2curves::bn256::{Bn256, G1Affine},
    rlc::virtual_region::RlcThreadBreakPoints,
    snark_verifier::{pcs::kzg::KzgDecidingKey, verifier::plonk::PlonkProtocol},
    utils::{
        build_utils::pinning::aggregation::{GenericAggParams, GenericAggPinning},
        keccak::decorator::RlcKeccakCircuitParams,
        snark_verifier::{AggregationCircuitParams, Base64Bytes},
    },
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Circuit parameters by node type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct CoreNodeParams {
    /// Type of the node in the aggregation tree.
    pub node_type: CoreNodeType,
    /// The maximum number of block headers in the chain at this level of the tree is 2<sup>depth</sup>.
    pub depth: usize,
    /// The leaf layer of the aggregation starts with max number of block headers equal to 2<sup>initial_depth</sup>.
    pub initial_depth: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum CoreNodeType {
    /// Leaf(max_extra_data_bytes)
    ///
    /// Different chains (e.g., Goerli) can have different maximum number of bytes in the extra data field of the block header.
    /// We configure the circuits differently based on this.
    Leaf(usize),
    /// Produces as many snarks as needed to fit the entire block number range, without any final processing.
    Intermediate,
    /// The block number range must fit within the specified max depth.
    /// Produces a single final snark with the starting & ending block numbers, previous and last block hashes,
    /// and merkle mountain range as output.
    Root,
    /// The block number range must fit within the specified max depth. `Evm(round)` performs `round + 1`
    /// rounds of SNARK verification on the final `Root` circuit
    Evm(usize),
}

impl CoreNodeParams {
    pub fn new(node_type: CoreNodeType, depth: usize, initial_depth: usize) -> Self {
        assert!(depth >= initial_depth);
        Self { node_type, depth, initial_depth }
    }

    pub fn child(&self, max_extra_data_bytes: Option<usize>) -> Option<Self> {
        match self.node_type {
            CoreNodeType::Leaf(_) => None,
            CoreNodeType::Intermediate | CoreNodeType::Root => {
                assert!(self.depth > self.initial_depth);
                if self.depth == self.initial_depth + 1 {
                    Some(Self::new(
                        CoreNodeType::Leaf(
                            max_extra_data_bytes.expect("must provide max_extra_data_bytes"),
                        ),
                        self.initial_depth,
                        self.initial_depth,
                    ))
                } else {
                    Some(Self::new(CoreNodeType::Intermediate, self.depth - 1, self.initial_depth))
                }
            }
            CoreNodeType::Evm(round) => {
                if round == 0 {
                    let node_type = if self.depth == self.initial_depth {
                        CoreNodeType::Leaf(
                            max_extra_data_bytes.expect("must provide max_extra_data_bytes"),
                        )
                    } else {
                        CoreNodeType::Root
                    };
                    Some(Self::new(node_type, self.depth, self.initial_depth))
                } else {
                    Some(Self::new(CoreNodeType::Evm(round - 1), self.depth, self.initial_depth))
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorePinningLeaf {
    pub num_instance: Vec<usize>,
    pub params: RlcKeccakCircuitParams,
    pub break_points: RlcThreadBreakPoints,
    /// g1 generator, g2 generator, s_g2 (s is generator of trusted setup).
    /// Together with domain size `2^k`, this commits to the trusted setup used.
    /// This is all that's needed to verify the final ecpairing check on the KZG proof.
    pub dk: KzgDecidingKey<Bn256>,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorePinningIntermediate {
    /// Configuration parameters
    pub params: AggregationCircuitParams,
    /// PlonkProtocol of the children
    #[serde_as(as = "Vec<Base64Bytes>")]
    pub to_agg: Vec<PlonkProtocol<G1Affine>>,
    /// Number of instances in each instance column
    pub num_instance: Vec<usize>,
    /// Break points. Should only have phase0, so MultiPhase is extraneous.
    pub break_points: MultiPhaseThreadBreakPoints,
    /// g1 generator, g2 generator, s_g2 (s is generator of trusted setup).
    /// Together with domain size `2^k`, this commits to the trusted setup used.
    /// This is all that's needed to verify the final ecpairing check on the KZG proof.
    pub dk: KzgDecidingKey<Bn256>,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorePinningRoot {
    /// Configuration parameters
    pub params: RlcKeccakCircuitParams,
    /// PlonkProtocol of the children
    #[serde_as(as = "Vec<Base64Bytes>")]
    pub to_agg: Vec<PlonkProtocol<G1Affine>>,
    /// Number of instances in each instance column
    pub num_instance: Vec<usize>,
    /// Break points.
    pub break_points: RlcThreadBreakPoints,
    /// g1 generator, g2 generator, s_g2 (s is generator of trusted setup).
    /// Together with domain size `2^k`, this commits to the trusted setup used.
    /// This is all that's needed to verify the final ecpairing check on the KZG proof.
    pub dk: KzgDecidingKey<Bn256>,
}

pub type CorePinningEvm = GenericAggPinning<GenericAggParams>;

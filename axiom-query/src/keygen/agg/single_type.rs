use std::{path::Path, sync::Arc};

use axiom_eth::{
    halo2_base::utils::halo2::ProvingKeyGenerator,
    halo2_proofs::plonk::ProvingKey,
    halo2curves::bn256::G1Affine,
    utils::{
        build_utils::{
            keygen::{read_srs_from_dir, write_pk_and_pinning},
            pinning::aggregation::{AggTreeId, GenericAggParams, GenericAggPinning},
        },
        merkle_aggregation::keygen::AggIntentMerkle,
    },
};
use enum_dispatch::enum_dispatch;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::keygen::{
    shard::{
        ShardIntentAccount, ShardIntentHeader, ShardIntentReceipt, ShardIntentResultsRoot,
        ShardIntentSolidityMapping, ShardIntentStorage, ShardIntentTx,
    },
    ProvingKeySerializer, ShardIntentECDSA, SupportedPinning,
};

use super::{common::parse_agg_intent, SupportedAggPinning};

#[derive(Serialize, Deserialize)]
#[enum_dispatch(ProvingKeySerializer)]
pub enum SupportedIntentTreeSingleType {
    Header(IntentTreeSingleType<ShardIntentHeader>),
    Account(IntentTreeSingleType<ShardIntentAccount>),
    Storage(IntentTreeSingleType<ShardIntentStorage>),
    Tx(IntentTreeSingleType<ShardIntentTx>),
    Receipt(IntentTreeSingleType<ShardIntentReceipt>),
    SolidityMapping(IntentTreeSingleType<ShardIntentSolidityMapping>),
    ECDSA(IntentTreeSingleType<ShardIntentECDSA>),
    ResultsRoot(IntentTreeSingleType<ShardIntentResultsRoot>),
}

/// Node in tree of aggregation intents. This is a complete tree
/// where the leaves all have the same configuration intent.
///
/// If we have a recursive chain `node0 -> node1 -> ... -> node_{m-1} -> leaf`,
/// then the tree has depth `m` and `node0.num_children * node1.num_children * ... * node_{m-1}.num_children` total leaves.
#[derive(Clone, Serialize, Deserialize)]
pub enum IntentTreeSingleType<LeafIntent> {
    Leaf(LeafIntent),
    Node(IntentNodeSingleType),
}

/// Node in aggregation tree which has `num_children` children (dependencies).
/// Each child has the same intent `child_intent`.
/// This struct is typeless and needs to be deserialized.
///
/// Typical use case: deserialize `child_intent` to `IntentTreeSingleType<LeafIntent>`
/// for recursive struct.
#[derive(Clone, Serialize, Deserialize)]
pub struct IntentNodeSingleType {
    /// log_2 domain size of the current aggregation circuit
    pub k: u32,
    /// Must be a power of 2
    pub num_children: usize,
    pub child_intent: serde_json::Value,
}

impl<LeafIntent> ProvingKeySerializer for IntentTreeSingleType<LeafIntent>
where
    LeafIntent: ProvingKeySerializer + DeserializeOwned,
{
    /// ## Assumptions
    /// - All pinnings have a "num_instance" field.
    fn create_and_serialize_proving_key(
        self,
        params_dir: &Path,
        data_dir: &Path,
    ) -> anyhow::Result<(AggTreeId, ProvingKey<G1Affine>, SupportedPinning)> {
        match self {
            IntentTreeSingleType::Leaf(intent) => {
                intent.create_and_serialize_proving_key(params_dir, data_dir)
            }
            IntentTreeSingleType::Node(node) => {
                let child_intent: IntentTreeSingleType<LeafIntent> =
                    serde_json::from_value(node.child_intent).unwrap();
                // Recursive call
                let (child_id, child_pk, child_pinning) =
                    child_intent.create_and_serialize_proving_key(params_dir, data_dir)?;
                let child_intent = parse_agg_intent(child_pk.get_vk(), child_pinning);
                let kzg_params = Arc::new(read_srs_from_dir(params_dir, node.k)?);
                let agg_intent = AggIntentMerkle {
                    kzg_params: kzg_params.clone(),
                    to_agg: vec![child_id.clone(); node.num_children],
                    deps: vec![child_intent; node.num_children],
                    k: node.k,
                };
                let (pk, pinning_json) = agg_intent.create_pk_and_pinning(&kzg_params);
                let pinning: GenericAggPinning<GenericAggParams> =
                    serde_json::from_value(pinning_json)?;
                let pinning =
                    SupportedPinning::Agg(SupportedAggPinning::SingleTypeAggregation(pinning));
                let circuit_id = write_pk_and_pinning(data_dir, &pk, &pinning)?;
                let tree_id = AggTreeId {
                    circuit_id,
                    children: vec![child_id; node.num_children],
                    aggregate_vk_hash: None,
                };
                Ok((tree_id, pk, pinning))
            }
        }
    }
}

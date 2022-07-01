use std::{collections::BTreeMap, path::Path, sync::Arc};

use axiom_eth::{
    halo2_base::gates::circuit::CircuitBuilderStage,
    halo2_proofs::{plonk::ProvingKey, poly::kzg::commitment::ParamsKZG},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    snark_verifier::verifier::plonk::PlonkProtocol,
    snark_verifier_sdk::{
        halo2::{
            aggregation::AggregationConfigParams,
            utils::{
                AggregationDependencyIntent, AggregationDependencyIntentOwned,
                KeygenAggregationCircuitIntent,
            },
        },
        Snark,
    },
    utils::{
        build_utils::{
            aggregation::get_dummy_aggregation_params,
            keygen::{compile_agg_dep_to_protocol, read_srs_from_dir},
            pinning::aggregation::{AggTreeId, GenericAggPinning},
        },
        snark_verifier::EnhancedSnark,
    },
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    keygen::{ProvingKeySerializer, SupportedPinning},
    subquery_aggregation::types::{
        InputSubqueryAggregation, SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX,
    },
};

use super::{
    common::{parse_agg_intent, ForceBasicConfigParams},
    impl_keygen_intent_for_aggregation, impl_pkey_serializer_for_aggregation,
    single_type::SupportedIntentTreeSingleType,
};

/// ** !! IMPORTANT !! **
/// Do not change the order of this enum, which determines how inputs are parsed.
// Determines order of circuit IDs in `to_agg`
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SubqueryAggInputSnark {
    Header,
    Account,
    Storage,
    Tx,
    Receipt,
    SolidityMapping,
    ResultsRoot,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SubqueryAggParams {
    /// The compiled verification keys of the dependency circuits to aggregate.
    /// Since Subquery Aggregation is universal aggregation, we remove the `domain` and `preprocessed` from `PlonkProtocol` since those
    /// are loaded as witness es.
    #[serde_as(as = "BTreeMap<_, axiom_eth::utils::snark_verifier::Base64Bytes>")]
    pub to_agg: BTreeMap<SubqueryAggInputSnark, PlonkProtocol<G1Affine>>,
    pub agg_params: AggregationConfigParams,
}

pub type SubqueryAggPinning = GenericAggPinning<SubqueryAggParams>;

/// Only implements [ProvingKeySerializer] and not [KeygenCircuitIntent].
#[derive(Serialize, Deserialize)]
pub struct RecursiveSubqueryAggIntent {
    pub deps: Vec<SupportedIntentTreeSingleType>,
    pub k: u32,
    /// For different versions of this circuit to be aggregated by the same universal aggregation circuit,
    /// we may wish to force configure the circuit to have a certain number of columns without auto-configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_params: Option<ForceBasicConfigParams>,
}

/// Non-recursive intent. Currently only used internally as an intermediary for recursive intent.
/// This will implement [KeygenCircuitIntent] where the pinning is not "wrapped" into an enum.
/// The pinning type is `GenericAggPinning<SubqueryAggParams>`.
#[derive(Clone, Debug)]
struct SubqueryAggIntent {
    // This is from bad UX; only svk = kzg_params.get_g()[0] is used
    pub kzg_params: Arc<ParamsKZG<Bn256>>,
    /// For passing to SubqueryAggParams via macro
    pub to_agg: BTreeMap<SubqueryAggInputSnark, PlonkProtocol<G1Affine>>,
    /// Circuit intents for subset of circuit types that are enabled
    pub deps: BTreeMap<SubqueryAggInputSnark, (AggTreeId, AggregationDependencyIntentOwned)>,
    /// The log_2 domain size of the current aggregation circuit
    pub k: u32,
    /// For different versions of this circuit to be aggregated by the same universal aggregation circuit,
    /// we may wish to force configure the circuit to have a certain number of columns without auto-configuration.
    pub force_params: Option<ForceBasicConfigParams>,
}

impl SubqueryAggIntent {
    pub fn children(&self) -> Vec<AggTreeId> {
        self.deps.values().map(|(tree, _)| tree.clone()).collect()
    }
}

impl KeygenAggregationCircuitIntent for SubqueryAggIntent {
    fn intent_of_dependencies(&self) -> Vec<AggregationDependencyIntent> {
        self.deps.values().map(|(_, d)| d.into()).collect()
    }
    fn build_keygen_circuit_from_snarks(self, snarks: Vec<Snark>) -> Self::AggregationCircuit {
        let mut deps = BTreeMap::from_iter(self.deps.keys().cloned().zip_eq(snarks));
        let mut remove_and_wrap =
            |k: &SubqueryAggInputSnark| deps.remove(k).map(|s| EnhancedSnark::new(s, None));
        // TODO: don't do manual conversion
        let snark_header = remove_and_wrap(&SubqueryAggInputSnark::Header);
        let snark_results_root = remove_and_wrap(&SubqueryAggInputSnark::ResultsRoot);
        let snark_account = remove_and_wrap(&SubqueryAggInputSnark::Account);
        let snark_storage = remove_and_wrap(&SubqueryAggInputSnark::Storage);
        let snark_tx = remove_and_wrap(&SubqueryAggInputSnark::Tx);
        let snark_receipt = remove_and_wrap(&SubqueryAggInputSnark::Receipt);
        let snark_solidity_mapping = remove_and_wrap(&SubqueryAggInputSnark::SolidityMapping);
        let promise_commit_keccak = Fr::zero(); // just a dummy

        let input = InputSubqueryAggregation {
            snark_header: snark_header.unwrap(),
            snark_account,
            snark_storage,
            snark_solidity_mapping,
            snark_tx,
            snark_receipt,
            promise_commit_keccak,
            snark_results_root: snark_results_root.unwrap(),
        };
        let mut force = false;
        let agg_params = if let Some(force_params) = self.force_params {
            force = true;
            force_params.into_agg_params(self.k)
        } else {
            get_dummy_aggregation_params(self.k as usize)
        };
        let mut circuit =
            input.build(CircuitBuilderStage::Keygen, agg_params, &self.kzg_params).unwrap();
        if !force {
            circuit.calculate_params(Some(20));
        }
        circuit
    }
}

impl_keygen_intent_for_aggregation!(
    SubqueryAggIntent,
    SubqueryAggParams,
    Some(SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX)
);
impl_pkey_serializer_for_aggregation!(SubqueryAggIntent, SubqueryAggParams, SubqueryAggregation);

fn get_key(supported: &SupportedIntentTreeSingleType) -> SubqueryAggInputSnark {
    type S = SupportedIntentTreeSingleType;
    type I = SubqueryAggInputSnark;
    match supported {
        S::Header(_) => I::Header,
        S::Account(_) => I::Account,
        S::Storage(_) => I::Storage,
        S::Tx(_) => I::Tx,
        S::Receipt(_) => I::Receipt,
        S::SolidityMapping(_) => I::SolidityMapping,
        S::ResultsRoot(_) => I::ResultsRoot,
    }
}

impl ProvingKeySerializer for RecursiveSubqueryAggIntent {
    fn create_and_serialize_proving_key(
        self,
        params_dir: &Path,
        data_dir: &Path,
    ) -> anyhow::Result<(AggTreeId, ProvingKey<G1Affine>, SupportedPinning)> {
        let mut deps = BTreeMap::new();
        for intent in self.deps {
            let key = get_key(&intent);
            let (child_tree_id, pk, pinning) =
                intent.create_and_serialize_proving_key(params_dir, data_dir)?;
            let intent = parse_agg_intent(pk.get_vk(), pinning);
            assert!(deps.insert(key, (child_tree_id, intent)).is_none());
        }
        let kzg_params = Arc::new(read_srs_from_dir(params_dir, self.k)?);
        let to_agg = deps
            .iter()
            .map(|(&k, (_, dep))| (k, compile_agg_dep_to_protocol(&kzg_params, dep, true)))
            .collect();
        let subquery_agg_intent = SubqueryAggIntent {
            to_agg,
            deps,
            k: self.k,
            kzg_params,
            force_params: self.force_params,
        };
        subquery_agg_intent.create_and_serialize_proving_key(params_dir, data_dir)
    }
}

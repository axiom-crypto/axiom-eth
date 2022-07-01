use std::{collections::BTreeMap, path::Path, sync::Arc};

use axiom_eth::{
    halo2_base::gates::circuit::CircuitBuilderStage,
    halo2_proofs::{plonk::ProvingKey, poly::kzg::commitment::ParamsKZG},
    halo2curves::bn256::{Bn256, G1Affine},
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
            pinning::aggregation::AggTreeId,
        },
        snark_verifier::EnhancedSnark,
    },
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    axiom_aggregation1::types::{InputAxiomAggregation1, FINAL_AGG_VKEY_HASH_IDX},
    keygen::{
        shard::{keccak::ShardIntentKeccak, CircuitIntentVerifyCompute},
        ProvingKeySerializer, SupportedPinning,
    },
    subquery_aggregation::types::SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX,
};

use super::{
    common::{parse_agg_intent, ForceBasicConfigParams},
    impl_keygen_intent_for_aggregation, impl_pkey_serializer_for_aggregation,
    single_type::IntentTreeSingleType,
    subquery_agg::RecursiveSubqueryAggIntent,
};

/// ** !! IMPORTANT !! **
/// Do not change the order of this enum, which determines how inputs are parsed.
// Determines order of circuit IDs in `to_agg`
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AxiomAgg1InputSnark {
    VerifyCompute,
    SubqueryAgg,
    Keccak,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AxiomAgg1Params {
    /// The compiled verification keys of the dependency circuits to aggregate.
    /// Since Axiom Aggregation 1 is universal aggregation, we remove the `domain` and `preprocessed` from `PlonkProtocol` since those
    /// are loaded as witnesses.
    #[serde_as(as = "BTreeMap<_, axiom_eth::utils::snark_verifier::Base64Bytes>")]
    pub to_agg: BTreeMap<AxiomAgg1InputSnark, PlonkProtocol<G1Affine>>,
    pub agg_params: AggregationConfigParams,
}

/// Only implements [ProvingKeySerializer] and not [KeygenCircuitIntent].
#[derive(Serialize, Deserialize)]
pub struct RecursiveAxiomAgg1Intent {
    pub intent_verify_compute: CircuitIntentVerifyCompute,
    pub intent_subquery_agg: RecursiveSubqueryAggIntent,
    pub intent_keccak: IntentTreeSingleType<ShardIntentKeccak>,
    pub k: u32,
    /// For different versions of this circuit to be aggregated by the same universal aggregation circuit,
    /// we may wish to force configure the circuit to have a certain number of columns without auto-configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_params: Option<ForceBasicConfigParams>,
}

/// Non-recursive intent. Currently only used internally as an intermediary for recursive intent.
/// This will implement [KeygenCircuitIntent] where the pinning is not "wrapped" into an enum.
/// The pinning type is `GenericAggPinning<AxiomAgg1Params>`.
#[derive(Clone, Debug)]
struct AxiomAgg1Intent {
    // This is from bad UX; only svk = kzg_params.get_g()[0] is used
    pub kzg_params: Arc<ParamsKZG<Bn256>>,
    /// For passing to AxiomAgg1Params via macro
    pub to_agg: BTreeMap<AxiomAgg1InputSnark, PlonkProtocol<G1Affine>>,
    /// Circuit intents for snarks to be aggregated by Axiom Aggregation 1
    pub deps: BTreeMap<AxiomAgg1InputSnark, (AggTreeId, AggregationDependencyIntentOwned)>,
    /// The log_2 domain size of the current aggregation circuit
    pub k: u32,
    /// For different versions of this circuit to be aggregated by the same universal aggregation circuit,
    /// we may wish to force configure the circuit to have a certain number of columns without auto-configuration.
    pub force_params: Option<ForceBasicConfigParams>,
}

impl AxiomAgg1Intent {
    pub fn children(&self) -> Vec<AggTreeId> {
        self.deps.values().map(|(tree, _)| tree.clone()).collect()
    }
}

impl KeygenAggregationCircuitIntent for AxiomAgg1Intent {
    fn intent_of_dependencies(&self) -> Vec<AggregationDependencyIntent> {
        self.deps.values().map(|(_, d)| d.into()).collect()
    }
    fn build_keygen_circuit_from_snarks(self, snarks: Vec<Snark>) -> Self::AggregationCircuit {
        let mut deps = BTreeMap::from_iter(self.deps.keys().cloned().zip_eq(snarks));
        let snark_verify_compute = deps.remove(&AxiomAgg1InputSnark::VerifyCompute).unwrap();
        let snark_subquery_agg = deps.remove(&AxiomAgg1InputSnark::SubqueryAgg).unwrap();
        let snark_keccak_agg = deps.remove(&AxiomAgg1InputSnark::Keccak).unwrap();

        // No agg_vkey_hash_idx because the compute_snark is separately tagged by the query_schema
        let snark_verify_compute = EnhancedSnark::new(snark_verify_compute, None);
        let snark_subquery_agg =
            EnhancedSnark::new(snark_subquery_agg, Some(SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX));
        let snark_keccak_agg = EnhancedSnark::new(snark_keccak_agg, None);

        let input =
            InputAxiomAggregation1 { snark_verify_compute, snark_subquery_agg, snark_keccak_agg };
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
    AxiomAgg1Intent,
    AxiomAgg1Params,
    Some(FINAL_AGG_VKEY_HASH_IDX)
);
impl_pkey_serializer_for_aggregation!(AxiomAgg1Intent, AxiomAgg1Params, AxiomAgg1);

impl ProvingKeySerializer for RecursiveAxiomAgg1Intent {
    fn create_and_serialize_proving_key(
        self,
        params_dir: &Path,
        data_dir: &Path,
    ) -> anyhow::Result<(AggTreeId, ProvingKey<G1Affine>, SupportedPinning)> {
        let mut deps = BTreeMap::new();
        fn process_intent(
            key: AxiomAgg1InputSnark,
            intent: impl ProvingKeySerializer,
            params_dir: &Path,
            data_dir: &Path,
            deps: &mut BTreeMap<AxiomAgg1InputSnark, (AggTreeId, AggregationDependencyIntentOwned)>,
        ) -> anyhow::Result<()> {
            let (tree_id, pk, pinning) =
                intent.create_and_serialize_proving_key(params_dir, data_dir)?;
            deps.insert(key, (tree_id, parse_agg_intent(pk.get_vk(), pinning)));
            Ok(())
        }
        process_intent(
            AxiomAgg1InputSnark::VerifyCompute,
            self.intent_verify_compute,
            params_dir,
            data_dir,
            &mut deps,
        )?;
        process_intent(
            AxiomAgg1InputSnark::SubqueryAgg,
            self.intent_subquery_agg,
            params_dir,
            data_dir,
            &mut deps,
        )?;
        process_intent(
            AxiomAgg1InputSnark::Keccak,
            self.intent_keccak,
            params_dir,
            data_dir,
            &mut deps,
        )?;
        let kzg_params = Arc::new(read_srs_from_dir(params_dir, self.k)?);
        let to_agg = deps
            .iter()
            .map(|(&k, (_, dep))| (k, compile_agg_dep_to_protocol(&kzg_params, dep, true)))
            .collect();
        let axiom_agg1_intent = AxiomAgg1Intent {
            to_agg,
            deps,
            k: self.k,
            kzg_params,
            force_params: self.force_params,
        };
        axiom_agg1_intent.create_and_serialize_proving_key(params_dir, data_dir)
    }
}

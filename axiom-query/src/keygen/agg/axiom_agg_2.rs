use std::{path::Path, sync::Arc};

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
use ethers_core::types::Address;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    axiom_aggregation1::types::FINAL_AGG_VKEY_HASH_IDX,
    axiom_aggregation2::circuit::InputAxiomAggregation2,
    keygen::{ProvingKeySerializer, SupportedPinning},
};

use super::{
    axiom_agg_1::RecursiveAxiomAgg1Intent,
    common::{parse_agg_intent, ForceBasicConfigParams},
    impl_keygen_intent_for_aggregation, impl_pkey_serializer_for_aggregation,
};

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AxiomAgg2Params {
    /// The compiled verification key of the dependency circuit to aggregate.
    /// Since Axiom Aggregation 2 is universal aggregation, we remove the `domain` and `preprocessed` from `PlonkProtocol` since those
    /// are loaded as witnesses.
    #[serde_as(as = "Box<axiom_eth::utils::snark_verifier::Base64Bytes>")]
    pub to_agg: Box<PlonkProtocol<G1Affine>>,
    pub agg_params: AggregationConfigParams,
}

/// Only implements [ProvingKeySerializer] and not [KeygenCircuitIntent].
#[derive(Serialize, Deserialize)]
pub struct RecursiveAxiomAgg2Intent {
    pub axiom_agg1_intent: RecursiveAxiomAgg1Intent,
    pub k: u32,
    /// Force the number of columns in the axiom agg 2 circuit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_params: Option<ForceBasicConfigParams>,
}

/// Non-recursive intent. Currently only used internally as an intermediary for recursive intent.
/// This will implement [KeygenCircuitIntent] where the pinning is not "wrapped" into an enum.
/// The pinning type is `GenericAggPinning<AxiomAgg2Params>`.
#[derive(Clone, Debug)]
struct AxiomAgg2Intent {
    // This is from bad UX; only svk = kzg_params.get_g()[0] is used
    pub kzg_params: Arc<ParamsKZG<Bn256>>,
    /// Circuit ID of the Axiom Aggregation 1 circuit
    pub child: AggTreeId,
    /// For passing to AxiomAgg2Params via macro
    pub to_agg: Box<PlonkProtocol<G1Affine>>,
    /// Circuit intent for Axiom Aggregation 1 circuit to be aggregated by Axiom Aggregation 2
    pub axiom_agg1_intent: AggregationDependencyIntentOwned,
    /// The log_2 domain size of the current aggregation circuit
    pub k: u32,
    /// Force the number of columns in the axiom agg 2 circuit.
    pub force_params: Option<ForceBasicConfigParams>,
}

impl AxiomAgg2Intent {
    pub fn children(&self) -> Vec<AggTreeId> {
        vec![self.child.clone()]
    }
}

impl KeygenAggregationCircuitIntent for AxiomAgg2Intent {
    fn intent_of_dependencies(&self) -> Vec<AggregationDependencyIntent> {
        vec![(&self.axiom_agg1_intent).into()]
    }
    fn build_keygen_circuit_from_snarks(self, mut snarks: Vec<Snark>) -> Self::AggregationCircuit {
        let snark_axiom_agg1 = snarks.pop().unwrap();
        let snark_axiom_agg1 = EnhancedSnark::new(snark_axiom_agg1, Some(FINAL_AGG_VKEY_HASH_IDX));

        let payee = Address::zero(); // dummy
        let input = InputAxiomAggregation2 { snark_axiom_agg1, payee };
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
    AxiomAgg2Intent,
    AxiomAgg2Params,
    Some(FINAL_AGG_VKEY_HASH_IDX)
);
impl_pkey_serializer_for_aggregation!(AxiomAgg2Intent, AxiomAgg2Params, AxiomAgg2);

impl ProvingKeySerializer for RecursiveAxiomAgg2Intent {
    fn create_and_serialize_proving_key(
        self,
        params_dir: &Path,
        data_dir: &Path,
    ) -> anyhow::Result<(AggTreeId, ProvingKey<G1Affine>, SupportedPinning)> {
        let (agg1_tree_id, pk, pinning) =
            self.axiom_agg1_intent.create_and_serialize_proving_key(params_dir, data_dir)?;
        let axiom_agg1_intent = parse_agg_intent(pk.get_vk(), pinning);
        let kzg_params = Arc::new(read_srs_from_dir(params_dir, self.k)?);
        let to_agg = compile_agg_dep_to_protocol(&kzg_params, &axiom_agg1_intent, true);
        let axiom_agg2_intent = AxiomAgg2Intent {
            kzg_params,
            child: agg1_tree_id,
            axiom_agg1_intent,
            to_agg: Box::new(to_agg),
            k: self.k,
            force_params: self.force_params,
        };
        axiom_agg2_intent.create_and_serialize_proving_key(params_dir, data_dir)
    }
}

use axiom_eth::utils::build_utils::pinning::aggregation::{GenericAggParams, GenericAggPinning};
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};

use self::{
    axiom_agg_1::AxiomAgg1Params, axiom_agg_2::AxiomAgg2Params, common::AggTreePinning,
    subquery_agg::SubqueryAggParams,
};

pub mod axiom_agg_1;
pub mod axiom_agg_2;
pub mod common;
pub mod single_type;
pub mod subquery_agg;

/// ** !! IMPORTANT !! **
/// Enum names are used to deserialize the pinning file. Please be careful if you need renaming.
#[derive(Serialize, Deserialize, Clone)]
#[enum_dispatch(AggTreePinning)]
pub enum SupportedAggPinning {
    AxiomAgg1(GenericAggPinning<AxiomAgg1Params>),
    AxiomAgg2(GenericAggPinning<AxiomAgg2Params>),
    SingleTypeAggregation(GenericAggPinning<GenericAggParams>),
    SubqueryAggregation(GenericAggPinning<SubqueryAggParams>),
}

/// # Assumptions
/// * $agg_params must have exactly the fields `to_agg, svk, agg_params`.
/// * $agg_intent must have a `to_agg` field of exactly the same type as $agg_params.
macro_rules! impl_keygen_intent_for_aggregation {
    ($agg_intent:ty, $agg_params:ident, $agg_vk_hash_idx:expr) => {
        impl
            axiom_eth::halo2_base::utils::halo2::KeygenCircuitIntent<
                axiom_eth::halo2curves::bn256::Fr,
            > for $agg_intent
        {
            type ConcreteCircuit =
                axiom_eth::snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
            /// We omit here tags (e.g., hash of vkeys) of the dependencies, they should be recorded separately.
            /// * The first coordinate is the `svk = kzg_params.get_g()[0]` of the KZG trusted setup used.
            /// * The second coordinate is `num_instance`.
            type Pinning =
                axiom_eth::utils::build_utils::pinning::aggregation::GenericAggPinning<$agg_params>;
            fn get_k(&self) -> u32 {
                self.k
            }
            fn build_keygen_circuit(self) -> Self::ConcreteCircuit {
                self.build_keygen_circuit_shplonk()
            }
            fn get_pinning_after_keygen(
                self,
                kzg_params: &axiom_eth::halo2_proofs::poly::kzg::commitment::ParamsKZG<
                    axiom_eth::halo2curves::bn256::Bn256,
                >,
                circuit: &Self::ConcreteCircuit,
            ) -> Self::Pinning {
                use axiom_eth::halo2_proofs::poly::commitment::ParamsProver;
                use axiom_eth::snark_verifier_sdk::CircuitExt;
                use axiom_eth::utils::build_utils::pinning::{
                    aggregation::GenericAggPinning, CircuitPinningInstructions,
                };
                use axiom_eth::utils::snark_verifier::NUM_FE_ACCUMULATOR;
                let pinning = circuit.pinning();
                let agg_params = $agg_params { to_agg: self.to_agg, agg_params: pinning.params };
                let svk = kzg_params.get_g()[0];
                let dk = (svk, kzg_params.g2(), kzg_params.s_g2());
                let agg_vk_hash_data = $agg_vk_hash_idx.map(|idx| {
                    let i = 0;
                    let j = NUM_FE_ACCUMULATOR + idx;
                    let agg_vk_hash = format!("{:?}", circuit.instances()[i][j]);
                    ((i, j), agg_vk_hash)
                });
                GenericAggPinning {
                    params: agg_params,
                    num_instance: circuit.num_instance(),
                    accumulator_indices: Self::ConcreteCircuit::accumulator_indices().unwrap(),
                    agg_vk_hash_data,
                    dk: dk.into(),
                    break_points: pinning.break_points,
                }
            }
        }
    };
}

/// A macro to auto-implement ProvingKeySerializer, where you specify which enum variant of SupportedAggPinning you want to use via $agg_pinning_name.
/// # Assumptions
/// * $agg_intent must have a `children()` function that returns `Vec<AggTreeId>` to give the child aggregation trees.
macro_rules! impl_pkey_serializer_for_aggregation {
    ($agg_intent:ty, $agg_params:ty, $agg_pinning_name:ident) => {
        impl crate::keygen::ProvingKeySerializer for $agg_intent {
            fn create_and_serialize_proving_key(
                self,
                params_dir: &std::path::Path,
                data_dir: &std::path::Path,
            ) -> anyhow::Result<(
                axiom_eth::utils::build_utils::pinning::aggregation::AggTreeId,
                axiom_eth::halo2_proofs::plonk::ProvingKey<axiom_eth::halo2curves::bn256::G1Affine>,
                crate::keygen::SupportedPinning,
            )> {
                use crate::keygen::{agg::SupportedAggPinning, SupportedPinning};
                use axiom_eth::halo2_base::utils::halo2::{
                    KeygenCircuitIntent, ProvingKeyGenerator,
                };
                use axiom_eth::utils::build_utils::{
                    keygen::{read_srs_from_dir, write_pk_and_pinning},
                    pinning::aggregation::{AggTreeId, GenericAggPinning},
                };
                let k = self.get_k();
                let children = self.children();
                let kzg_params = read_srs_from_dir(params_dir, k)?;
                let (pk, pinning_json) = self.create_pk_and_pinning(&kzg_params);
                let pinning: GenericAggPinning<$agg_params> = serde_json::from_value(pinning_json)?;
                let aggregate_vk_hash = pinning.agg_vk_hash_data.as_ref().map(|x| x.1.clone());
                let pinning =
                    SupportedPinning::Agg(SupportedAggPinning::$agg_pinning_name(pinning));
                let circuit_id =
                    write_pk_and_pinning(data_dir, &pk, &serde_json::to_value(&pinning)?)?;
                let tree_id = AggTreeId { circuit_id, children, aggregate_vk_hash };
                Ok((tree_id, pk, pinning))
            }
        }
    };
}

pub(crate) use impl_keygen_intent_for_aggregation;
pub(crate) use impl_pkey_serializer_for_aggregation;

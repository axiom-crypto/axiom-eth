use axiom_eth::{
    halo2_proofs::plonk::VerifyingKey,
    halo2curves::{
        bn256::{Fr, G1Affine},
        ff::PrimeField,
    },
    snark_verifier_sdk::halo2::{
        aggregation::AggregationConfigParams, utils::AggregationDependencyIntentOwned,
    },
    utils::build_utils::pinning::aggregation::GenericAggPinning,
};
use enum_dispatch::enum_dispatch;
use hex::FromHex;
use serde::{Deserialize, Serialize};

/// Fields of [`AggregationConfigParams`] besides `degree` and `lookup_bits`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ForceBasicConfigParams {
    pub num_advice: usize,
    pub num_lookup_advice: usize,
    pub num_fixed: usize,
}

impl ForceBasicConfigParams {
    pub fn into_agg_params(self, k: u32) -> AggregationConfigParams {
        AggregationConfigParams {
            degree: k,
            lookup_bits: k as usize - 1,
            num_advice: self.num_advice,
            num_lookup_advice: self.num_lookup_advice,
            num_fixed: self.num_fixed,
        }
    }
}

// enum_dispatch cannot cross crates, so we need to define the trait here
/// Trait for a pinning for a node in the aggregation tree. It may or may not be for an aggregation circuit.
#[enum_dispatch]
pub trait AggTreePinning {
    fn num_instance(&self) -> Vec<usize>;
    fn accumulator_indices(&self) -> Option<Vec<(usize, usize)>>;
    /// Aggregate vk hash, if universal aggregation circuit.
    /// * ((i, j), agg_vkey_hash), where the hash is located at (i, j) in the public instance columns
    fn agg_vk_hash_data(&self) -> Option<((usize, usize), axiom_eth::halo2curves::bn256::Fr)>;
}

pub fn parse_agg_intent(
    vk: &VerifyingKey<G1Affine>,
    pinning: impl AggTreePinning,
) -> AggregationDependencyIntentOwned {
    let num_instance = pinning.num_instance();
    let accumulator_indices = pinning.accumulator_indices();
    AggregationDependencyIntentOwned {
        vk: vk.clone(),
        num_instance,
        accumulator_indices,
        agg_vk_hash_data: pinning.agg_vk_hash_data(),
    }
}

impl<AggParams> AggTreePinning for GenericAggPinning<AggParams> {
    fn num_instance(&self) -> Vec<usize> {
        self.num_instance.clone()
    }
    fn accumulator_indices(&self) -> Option<Vec<(usize, usize)>> {
        Some(self.accumulator_indices.clone())
    }
    fn agg_vk_hash_data(&self) -> Option<((usize, usize), Fr)> {
        // agg_vk_hash in pinning is represented in big endian for readability
        self.agg_vk_hash_data.as_ref().map(|((i, j), hash_str)| {
            assert_eq!(&hash_str[..2], "0x");
            let mut bytes_be = Vec::from_hex(&hash_str[2..]).unwrap();
            bytes_be.reverse();
            let bytes_le = bytes_be;
            let agg_vkey_hash = Fr::from_repr(bytes_le.try_into().unwrap()).unwrap();
            ((*i, *j), agg_vkey_hash)
        })
    }
}

#[cfg(test)]
#[test]
fn test_parse_agg_intent() {
    use axiom_eth::{
        halo2curves::{bn256::G2Affine, ff::Field},
        utils::build_utils::{
            aggregation::get_dummy_aggregation_params, pinning::aggregation::GenericAggParams,
        },
    };
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    let params = GenericAggParams { to_agg: vec![], agg_params: get_dummy_aggregation_params(10) };
    let mut rng = StdRng::seed_from_u64(0);
    let agg_vk_hash = Fr::random(&mut rng);
    let agg_pinning = GenericAggPinning {
        params,
        num_instance: vec![1],
        accumulator_indices: (0..12).map(|j| (0, j)).collect(),
        agg_vk_hash_data: Some(((0, 0), format!("{:?}", agg_vk_hash))),
        dk: (G1Affine::generator(), G2Affine::generator(), G2Affine::random(&mut rng)).into(),
        break_points: Default::default(),
    };
    assert_eq!(agg_pinning.agg_vk_hash_data(), Some(((0, 0), agg_vk_hash)));
}

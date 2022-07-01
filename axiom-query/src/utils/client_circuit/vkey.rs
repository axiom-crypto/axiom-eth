use std::io::Read;

use anyhow::Result;
use axiom_codec::utils::reader::{read_curve_compressed, read_field_le, read_h256};
use axiom_eth::{
    halo2_proofs::poly::kzg::commitment::ParamsKZG,
    halo2curves::{
        bn256::{Bn256, G1Affine},
        CurveAffine,
    },
    snark_verifier::{
        system::halo2::{compile, Config},
        util::arithmetic::{root_of_unity, Domain},
        verifier::plonk::PlonkProtocol,
    },
    snark_verifier_sdk::{halo2::aggregation::AggregationCircuit, CircuitExt},
};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};

use super::{
    default_circuit::{dummy_vk_from_metadata, DUMMY_K},
    metadata::{decode_axiom_v2_circuit_metadata, AxiomV2CircuitMetadata},
};

#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
pub struct OnchainVerifyingKey<C: CurveAffine> {
    pub circuit_metadata: AxiomV2CircuitMetadata,
    pub transcript_initial_state: C::Scalar,
    pub preprocessed: Vec<C>,
}

impl<C: CurveAffine> OnchainVerifyingKey<C> {
    pub fn read(reader: &mut impl Read) -> Result<Self>
    where
        C::Scalar: axiom_codec::Field,
    {
        let encoded_circuit_metadata = read_h256(reader)?;
        let circuit_metadata = decode_axiom_v2_circuit_metadata(encoded_circuit_metadata)?;

        let transcript_initial_state = read_field_le(reader)?;
        let mut preprocessed = Vec::new();
        while let Ok(point) = read_curve_compressed(reader) {
            preprocessed.push(point);
        }
        Ok(OnchainVerifyingKey { circuit_metadata, preprocessed, transcript_initial_state })
    }
}

impl OnchainVerifyingKey<G1Affine> {
    // @dev Remark: PlonkProtocol fields are public so we can perform "surgery" on them, whereas halo2 VerifyingKey has all fields private so we can't.
    pub fn into_plonk_protocol(self, k: usize) -> Result<PlonkProtocol<G1Affine>> {
        let OnchainVerifyingKey { circuit_metadata, transcript_initial_state, preprocessed } = self;
        // We can make a dummy trusted setup here because we replace the fixed commitments afterwards
        let kzg_params = ParamsKZG::<Bn256>::setup(DUMMY_K, StdRng::seed_from_u64(0));
        let dummy_vk = dummy_vk_from_metadata(&kzg_params, circuit_metadata.clone())?;
        let num_instance = circuit_metadata.num_instance.iter().map(|x| *x as usize).collect();
        let acc_indices = circuit_metadata
            .is_aggregation
            .then(|| AggregationCircuit::accumulator_indices().unwrap());
        let mut protocol = compile(
            &kzg_params,
            &dummy_vk,
            Config::kzg().with_num_instance(num_instance).with_accumulator_indices(acc_indices),
        );
        // See [snark_verifier::system::halo2::compile] to see how [PlonkProtocol] is constructed
        // These are the parts of `protocol` that are different for different vkeys or different `k`
        protocol.domain = Domain::new(k, root_of_unity(k));
        protocol.domain_as_witness = None;
        protocol.preprocessed = preprocessed;
        protocol.transcript_initial_state = Some(transcript_initial_state);
        // Do not MSM public instances (P::QUERY_INSTANCE should be false)
        protocol.instance_committing_key = None;
        protocol.linearization = None;
        Ok(protocol)
    }
}

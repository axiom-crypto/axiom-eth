use std::{hash::Hash, io::Write};

use anyhow::{anyhow, bail};
use axiom_codec::{
    constants::{
        USER_ADVICE_COLS, USER_FIXED_COLS, USER_INSTANCE_COLS, USER_LOOKUP_ADVICE_COLS,
        USER_MAX_OUTPUTS, USER_MAX_SUBQUERIES, USER_RESULT_FIELD_ELEMENTS,
    },
    decoder::native::decode_compute_snark,
    types::{
        field_elements::SUBQUERY_RESULT_LEN,
        native::{AxiomV2ComputeQuery, AxiomV2ComputeSnark},
    },
    utils::writer::{write_curve_compressed, write_field_le},
    HiLo,
};
use axiom_eth::{
    halo2_base::{
        gates::circuit::{builder::BaseCircuitBuilder, BaseCircuitParams},
        halo2_proofs::{
            halo2curves::{
                bn256::{Bn256, Fr},
                ff::PrimeField,
                serde::SerdeObject,
                CurveAffine,
            },
            plonk::VerifyingKey,
        },
        utils::ScalarField,
    },
    halo2curves::{bn256::G1Affine, ff::Field as _},
    rlc::circuit::RlcCircuitParams,
    snark_verifier::{
        pcs::kzg::KzgDecidingKey,
        system::halo2::transcript_initial_state,
        util::arithmetic::fe_to_limbs,
        verifier::{
            plonk::{PlonkProof, PlonkProtocol},
            SnarkVerifier,
        },
    },
    snark_verifier_sdk::{
        halo2::{aggregation::AggregationCircuit, PoseidonTranscript, POSEIDON_SPEC},
        CircuitExt, NativeLoader, PlonkVerifier, Snark, BITS, LIMBS, SHPLONK,
    },
};
use ethers_core::types::H256;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    components::results::types::{CircuitOutputResultsRoot, LogicOutputResultsRoot},
    utils::client_circuit::{metadata::AxiomV2CircuitMetadata, vkey::OnchainVerifyingKey},
    Field,
};

/// Need to provide RlcCircuitParams for additional context, otherwise you have
/// to parse the RlcCircuitParams data from the custom gate information in `protocol`
pub fn get_metadata_from_protocol(
    protocol: &PlonkProtocol<G1Affine>,
    rlc_params: RlcCircuitParams,
    max_outputs: usize,
) -> anyhow::Result<AxiomV2CircuitMetadata> {
    let num_advice_per_phase =
        rlc_params.base.num_advice_per_phase.iter().map(|x| *x as u16).collect();
    let num_lookup_advice_per_phase =
        rlc_params.base.num_lookup_advice_per_phase.iter().map(|x| *x as u8).collect();
    let num_rlc_columns = rlc_params.num_rlc_columns as u16;
    let num_fixed = rlc_params.base.num_fixed as u8;
    let mut metadata = AxiomV2CircuitMetadata {
        version: 0,
        num_advice_per_phase,
        num_lookup_advice_per_phase,
        num_rlc_columns,
        num_fixed,
        max_outputs: max_outputs as u16,
        ..Default::default()
    };

    if protocol.num_instance.len() != 1 {
        bail!("Only one instance column supported right now");
    }
    metadata.num_instance = protocol.num_instance.iter().map(|&x| x as u32).collect();
    let mut num_challenge_incl_system = protocol.num_challenge.clone();
    // This `num_challenge` counts only the challenges used inside the circuit - it excludes challenges that are part of the halo2 system.
    // The full challenges, which is what `plonk_protocol.num_challenge` stores, is:
    // ```ignore
    // [
    //   my_phase0_challenges,
    //   ...
    //   [..my_phasen_challenges, theta],
    //   [beta, gamma],
    //   [alpha],
    // ]
    // ```
    if num_challenge_incl_system.pop() != Some(1) {
        bail!("last challenge must be [alpha]");
    }
    if num_challenge_incl_system.pop() != Some(2) {
        bail!("second last challenge must be [beta, gamma]");
    }
    let last_challenge = num_challenge_incl_system.last_mut();
    if last_challenge.is_none() {
        bail!("num_challenge must have at least 3 challenges");
    }
    let last_challenge = last_challenge.unwrap();
    if *last_challenge == 0 {
        bail!("third last challenge must include theta");
    }
    *last_challenge -= 1;
    let num_challenge: Vec<u8> = num_challenge_incl_system.iter().map(|x| *x as u8).collect();
    if num_challenge != vec![0] && num_challenge != vec![1, 0] {
        log::debug!("num_challenge: {:?}", num_challenge);
        bail!("Only phase0 BaseCircuitBuilder or phase0+1 RlcCircuitBuilder supported right now");
    }
    metadata.num_challenge = num_challenge;

    metadata.is_aggregation = if protocol.accumulator_indices.is_empty() {
        false
    } else {
        if protocol.accumulator_indices.len() != 1
            || protocol.accumulator_indices[0] != AggregationCircuit::accumulator_indices().unwrap()
        {
            bail!("invalid accumulator indices");
        }
        true
    };

    Ok(metadata)
}

/// Reference implementation. Actually done by axiom-sdk-client
pub fn write_onchain_vkey<C>(vkey: &OnchainVerifyingKey<C>) -> anyhow::Result<Vec<H256>>
where
    C: CurveAffine + SerdeObject,
    C::Scalar: Field + SerdeObject,
{
    let metadata = vkey.circuit_metadata.encode()?;

    let tmp = C::Repr::default();
    let compressed_curve_bytes = tmp.as_ref().len();
    let tmp = <C::Scalar as PrimeField>::Repr::default();
    let field_bytes = tmp.as_ref().len();
    let mut writer =
        Vec::with_capacity(field_bytes + vkey.preprocessed.len() * compressed_curve_bytes);

    writer.write_all(&metadata.to_fixed_bytes())?;
    write_field_le(&mut writer, vkey.transcript_initial_state)?;
    for &point in &vkey.preprocessed {
        write_curve_compressed(&mut writer, point)?;
    }
    Ok(writer.chunks_exact(32).map(H256::from_slice).collect())
}

/// Requires additional context about the Axiom circuit, in the form of the `circuit_metadata`.
pub fn get_onchain_vk_from_vk<C: CurveAffine>(
    vk: &VerifyingKey<C>,
    circuit_metadata: AxiomV2CircuitMetadata,
) -> OnchainVerifyingKey<C> {
    let preprocessed = vk
        .fixed_commitments()
        .iter()
        .chain(vk.permutation().commitments().iter())
        .cloned()
        .map(Into::into)
        .collect();
    let transcript_initial_state = transcript_initial_state(vk);
    OnchainVerifyingKey { circuit_metadata, preprocessed, transcript_initial_state }
}

pub fn get_onchain_vk_from_protocol<C: CurveAffine>(
    protocol: &PlonkProtocol<C>,
    circuit_metadata: AxiomV2CircuitMetadata,
) -> OnchainVerifyingKey<C> {
    let preprocessed = protocol.preprocessed.clone();
    let transcript_initial_state = protocol.transcript_initial_state.unwrap();
    OnchainVerifyingKey { circuit_metadata, preprocessed, transcript_initial_state }
}

pub fn reconstruct_snark_from_compute_query(
    subquery_results: LogicOutputResultsRoot,
    compute_query: AxiomV2ComputeQuery,
) -> anyhow::Result<(Snark, AxiomV2CircuitMetadata)> {
    let subquery_results = CircuitOutputResultsRoot::<Fr>::try_from(subquery_results)?;
    let vkey = compute_query.vkey.into_iter().flat_map(|u| u.0).collect_vec();
    let mut reader = &vkey[..];
    let onchain_vk = OnchainVerifyingKey::<G1Affine>::read(&mut reader)?;
    let client_metadata = onchain_vk.circuit_metadata.clone();
    let k = compute_query.k as usize;
    let protocol = onchain_vk.into_plonk_protocol(k)?;

    // === Begin reconstruct proof transcript: ===
    if client_metadata.num_instance.len() != 1 {
        bail!("Only one instance column supported right now");
    }
    let num_instance = client_metadata.num_instance[0] as usize;

    // We assume that the true number of user requested subqueries is `num_subqueries`
    let num_subqueries = subquery_results.num_subqueries;
    let result_len = compute_query.result_len as usize;
    let max_outputs = client_metadata.max_outputs as usize;
    if result_len > max_outputs {
        bail!("user_output_len exceeds user max outputs");
    }
    // compute proof only has the user outputs, not the user subquery requests
    let mut reader = &compute_query.compute_proof[..];
    let AxiomV2ComputeSnark { compute_results, proof_transcript, kzg_accumulator } =
        decode_compute_snark(
            &mut reader,
            compute_query.result_len,
            client_metadata.is_aggregation,
        )?;
    let mut instance = Vec::with_capacity(num_instance);
    if let Some((lhs, rhs)) = kzg_accumulator {
        instance.extend(
            [lhs.x, lhs.y, rhs.x, rhs.y].into_iter().flat_map(fe_to_limbs::<_, Fr, LIMBS, BITS>),
        );
    }
    let mut compute_results =
        compute_results.into_iter().flat_map(|out| HiLo::from(out).hi_lo()).collect_vec();
    // safety check that user outputs are hardcoded to HiLo for now
    assert_eq!(compute_results.len(), result_len * USER_RESULT_FIELD_ELEMENTS);
    compute_results
        .resize((client_metadata.max_outputs as usize) * USER_RESULT_FIELD_ELEMENTS, Fr::ZERO);
    instance.extend(compute_results);

    // fill in public instances corresponding to subqueries
    for result in &subquery_results.results.rows[..num_subqueries] {
        instance.extend(result.to_fixed_array());
    }
    if instance.len() > num_instance {
        bail!("Num subqueries exceeds num_instance limit");
    }
    instance.resize(num_instance, Fr::ZERO);
    let snark = Snark::new(protocol, vec![instance], proof_transcript);
    Ok((snark, client_metadata))
}

/// This verifies snark with poseidon transcript and **importantly** also checks the
/// kzg accumulator from the public instances, if `snark` is aggregation circuit
pub fn verify_snark(dk: &KzgDecidingKey<Bn256>, snark: &Snark) -> anyhow::Result<()> {
    let mut transcript =
        PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(snark.proof(), POSEIDON_SPEC.clone());
    let proof: PlonkProof<_, _, SHPLONK> =
        PlonkVerifier::read_proof(dk, &snark.protocol, &snark.instances, &mut transcript)
            .map_err(|_| anyhow!("Failed to read PlonkProof"))?;
    PlonkVerifier::verify(dk, &snark.protocol, &snark.instances, &proof)
        .map_err(|_| anyhow!("PlonkVerifier failed"))?;
    Ok(())
}

lazy_static::lazy_static! {
    pub static ref DEFAULT_CLIENT_METADATA: AxiomV2CircuitMetadata = AxiomV2CircuitMetadata {
        version: 0,
        num_advice_per_phase: vec![USER_ADVICE_COLS as u16],
        num_lookup_advice_per_phase: vec![USER_LOOKUP_ADVICE_COLS as u8],
        num_rlc_columns: 0,
        num_fixed: USER_FIXED_COLS as u8,
        num_instance: vec![
            (USER_MAX_OUTPUTS * USER_RESULT_FIELD_ELEMENTS + USER_MAX_SUBQUERIES * SUBQUERY_RESULT_LEN)
                as u32,
        ],
        num_challenge: vec![0],
        max_outputs: USER_MAX_OUTPUTS as u16,
        is_aggregation: false,
    };
}

/// Fully describes the configuration of a user provided circuit written using [`halo2_base`](axiom_eth::halo2_base) or [`snark_verifier_sdk`](axiom_eth::snark_verifier_sdk).
#[derive(Clone, Copy, Debug, Hash, Serialize, Deserialize)]
pub struct UserCircuitParams {
    pub num_advice_cols: usize,
    pub num_lookup_advice_cols: usize,
    pub num_fixed_cols: usize,
    /// Max number of bytes32 the user can output.
    /// This will be `2 * USER_MAX_OUTPUTS` field elements as public instances.
    pub max_outputs: usize,
    /// Maximum number of subqueries a user can request.
    pub max_subqueries: usize,
}

impl UserCircuitParams {
    /// Total public instances of the user circuit.
    /// We start with
    /// - user outputs (bytes32 in HiLo, 2 field elements each) and then
    /// - add the "flattened" user subqueries with results
    ///
    /// Currently we assume user circuit has a single instance column.
    pub fn num_instances(&self) -> usize {
        self.max_outputs * USER_RESULT_FIELD_ELEMENTS + self.max_subqueries * SUBQUERY_RESULT_LEN
    }

    pub fn base_circuit_params(&self, k: usize) -> BaseCircuitParams {
        BaseCircuitParams {
            k,
            num_advice_per_phase: vec![self.num_advice_cols],
            num_lookup_advice_per_phase: vec![self.num_lookup_advice_cols],
            num_fixed: self.num_fixed_cols,
            lookup_bits: Some(k - 1),
            num_instance_columns: USER_INSTANCE_COLS,
        }
    }
}

pub const DEFAULT_USER_PARAMS: UserCircuitParams = UserCircuitParams {
    num_advice_cols: USER_ADVICE_COLS,
    num_lookup_advice_cols: USER_LOOKUP_ADVICE_COLS,
    num_fixed_cols: USER_FIXED_COLS,
    max_outputs: USER_MAX_OUTPUTS,
    max_subqueries: USER_MAX_SUBQUERIES,
};

/// Creates a default snark for a [axiom_eth::halo2_base] circuit with a fixed configuration,
/// using the given trusted setup. The log2 domain size `params.k()` can be variable.
/// Used to get fixed constraint and gate information.
pub fn dummy_compute_circuit<F: ScalarField>(
    user_params: UserCircuitParams,
    k: u32,
) -> BaseCircuitBuilder<F> {
    let circuit_params = user_params.base_circuit_params(k as usize);
    let mut builder = BaseCircuitBuilder::new(false).use_params(circuit_params);

    let ctx = builder.main(0);
    let dummy_instances = ctx.assign_witnesses(vec![F::ZERO; user_params.num_instances()]);
    assert_eq!(builder.assigned_instances.len(), USER_INSTANCE_COLS);
    builder.assigned_instances[0] = dummy_instances;

    builder
}

pub fn default_compute_circuit(k: u32) -> BaseCircuitBuilder<Fr> {
    dummy_compute_circuit(DEFAULT_USER_PARAMS, k)
}

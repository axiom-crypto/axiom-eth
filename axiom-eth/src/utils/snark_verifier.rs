use std::hash::Hash;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as, DeserializeAs, SerializeAs};
use snark_verifier::verifier::plonk::PlonkProtocol;

use crate::{
    halo2_base::{
        gates::{
            circuit::CircuitBuilderStage, flex_gate::threads::SinglePhaseCoreManager, GateChip,
            GateInstructions, RangeChip, RangeInstructions,
        },
        halo2_proofs::{
            halo2curves::bn256::{Bn256, Fr},
            poly::kzg::commitment::ParamsKZG,
        },
        poseidon::hasher::PoseidonSponge,
        AssignedValue, Context,
    },
    halo2curves::bn256::G1Affine,
    snark_verifier_sdk::{
        halo2::{
            aggregation::{
                aggregate_snarks, AggregationCircuit, AggregationConfigParams,
                AssignedTranscriptObject, Halo2KzgAccumulationScheme,
                PreprocessedAndDomainAsWitness, SnarkAggregationOutput, Svk, VerifierUniversality,
            },
            POSEIDON_SPEC,
        },
        Snark, LIMBS,
    },
};
#[cfg(feature = "evm")]
use ethers_core::types::Bytes;
#[cfg(feature = "evm")]
use halo2_base::halo2_proofs::plonk::ProvingKey;
#[cfg(feature = "evm")]
use snark_verifier_sdk::{
    evm::{encode_calldata, gen_evm_proof_shplonk},
    CircuitExt,
};

pub type AggregationCircuitParams = AggregationConfigParams;

pub const NUM_FE_ACCUMULATOR: usize = 4 * LIMBS;

type F = Fr;

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnhancedSnark {
    #[serde_as(as = "Base64Bytes")]
    pub inner: Snark,
    /// If this snark is a **universal** aggregation circuit, then it must expose an
    /// `agg_vk_hash` in its public instances. In that case `agg_vk_hash_idx = Some(idx)`,
    /// where `flattened_instances[idx]` is the `agg_vk_hash` and `flattened_instances` are the
    /// instances **with the old accumulator removed**.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agg_vk_hash_idx: Option<usize>,
}

impl EnhancedSnark {
    pub fn new(snark: Snark, agg_vk_hash_idx: Option<usize>) -> Self {
        Self { inner: snark, agg_vk_hash_idx }
    }
}

impl AsRef<EnhancedSnark> for EnhancedSnark {
    fn as_ref(&self) -> &EnhancedSnark {
        self
    }
}
impl AsRef<Snark> for EnhancedSnark {
    fn as_ref(&self) -> &Snark {
        &self.inner
    }
}

/// **Private** witnesses that form the output of [aggregate_enhanced_snarks].
#[derive(Clone, Debug)]
pub struct EnhancedSnarkAggregationOutput {
    /// We remove the old accumulators from the previous instances using `has_accumulator` from
    /// the previous [EnhancedSnark]s
    pub previous_instances: Vec<Vec<AssignedValue<F>>>,
    pub accumulator: Vec<AssignedValue<F>>,
    /// This is the single Poseidon hash of all previous `agg_vk_hash` in previously aggregated
    /// universal aggregation snarks, together with the preprocessed digest and transcript initial state
    /// (aka partial vkey) from the enhanced snarks that were aggregated.
    pub agg_vk_hash: AssignedValue<F>,
    /// The proof transcript, as loaded scalars and elliptic curve points, for each SNARK that was aggregated.
    pub proof_transcripts: Vec<Vec<AssignedTranscriptObject>>,
}

/// Aggregate enhanced snarks as a universal aggregation circuit, taking care to
/// compute the new `agg_vk_hash` by hashing together all previous `agg_vk_hash`s and partial vkeys.
pub fn aggregate_enhanced_snarks<AS>(
    pool: &mut SinglePhaseCoreManager<F>,
    range: &RangeChip<F>,
    svk: Svk, // gotten by params.get_g()[0].into()
    snarks: &[impl AsRef<EnhancedSnark>],
) -> EnhancedSnarkAggregationOutput
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
{
    let SnarkAggregationOutput { previous_instances, accumulator, preprocessed, proof_transcripts } =
        aggregate_snarks::<AS>(
            pool,
            range,
            svk,
            snarks.iter().map(|s| s.as_ref().inner.clone()),
            VerifierUniversality::Full,
        );
    let prev_acc_indices = get_accumulator_indices(snarks.iter().map(|s| &s.as_ref().inner));
    let ctx = pool.main();
    let (previous_instances, agg_vk_hash) = process_prev_instances_and_calc_agg_vk_hash(
        ctx,
        range.gate(),
        previous_instances,
        preprocessed,
        &prev_acc_indices,
        snarks.iter().map(|s| s.as_ref().agg_vk_hash_idx),
    );
    EnhancedSnarkAggregationOutput {
        previous_instances,
        accumulator,
        agg_vk_hash,
        proof_transcripts,
    }
}

/// Returns `(circuit, prev_instances, agg_vkey_hash)` where `prev_instances` has old accumulators removed.
///
/// ### Previous `agg_vkey_hash` indices
/// If a snark in `snarks` is a **universal** aggregation circuit, then it **must** expose an
/// `agg_vkey_hash` in its public instances. In that case `agg_vkey_hash_idx = Some(idx)`,
/// where `flattened_instances[idx]` is the `agg_vkey_hash` and `flattened_instances` are the
/// instances of the snark **with the old accumulator removed**.
pub fn create_universal_aggregation_circuit<AS>(
    stage: CircuitBuilderStage,
    circuit_params: AggregationCircuitParams,
    kzg_params: &ParamsKZG<Bn256>,
    snarks: Vec<Snark>,
    agg_vkey_hash_indices: Vec<Option<usize>>,
) -> (AggregationCircuit, Vec<Vec<AssignedValue<F>>>, AssignedValue<F>)
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
{
    assert_eq!(snarks.len(), agg_vkey_hash_indices.len());
    let prev_acc_indices = get_accumulator_indices(&snarks);
    let mut circuit = AggregationCircuit::new::<AS>(
        stage,
        circuit_params,
        kzg_params,
        snarks,
        VerifierUniversality::Full,
    );

    let prev_instances = circuit.previous_instances().clone();
    let preprocessed = circuit.preprocessed().clone();
    let builder = &mut circuit.builder;
    let ctx = builder.main(0);
    let gate = GateChip::default();
    let (previous_instances, agg_vkey_hash) = process_prev_instances_and_calc_agg_vk_hash(
        ctx,
        &gate,
        prev_instances,
        preprocessed,
        &prev_acc_indices,
        agg_vkey_hash_indices,
    );
    (circuit, previous_instances, agg_vkey_hash)
}

/// Calculate agg_vk_hash and simultaneously remove old accumulators from previous_instances
///
/// Returns `previous_instances` with old accumulators at `prev_accumulator_indices` removed, and returns the new `agg_vk_hash`
pub fn process_prev_instances_and_calc_agg_vk_hash(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    mut prev_instances: Vec<Vec<AssignedValue<F>>>,
    preprocessed: Vec<PreprocessedAndDomainAsWitness>,
    prev_accumulator_indices: &[Vec<usize>],
    prev_agg_vk_hash_indices: impl IntoIterator<Item = Option<usize>>,
) -> (Vec<Vec<AssignedValue<F>>>, AssignedValue<F>) {
    let mut sponge = PoseidonSponge::from_spec(ctx, POSEIDON_SPEC.clone());
    for (((prev_instance, partial_vk), acc_indices), agg_vk_hash_idx) in prev_instances
        .iter_mut()
        .zip_eq(preprocessed)
        .zip_eq(prev_accumulator_indices)
        .zip_eq(prev_agg_vk_hash_indices)
    {
        sponge.update(&[partial_vk.k]);
        sponge.update(&partial_vk.preprocessed);
        for i in acc_indices.iter().sorted().rev() {
            prev_instance.remove(*i);
        }
        if let Some(agg_vk_hash_idx) = agg_vk_hash_idx {
            assert!(!acc_indices.is_empty());
            sponge.update(&[prev_instance[agg_vk_hash_idx]]);
        }
    }
    let agg_vk_hash = sponge.squeeze(ctx, gate);
    (prev_instances, agg_vk_hash)
}

/// Returns the indices of the accumulator, if any, for each snark **in sorted (increasing) order**.
///
/// ## Panics
/// Panics if any snark has accumulator indices not in instance column 0.
pub fn get_accumulator_indices<'a>(snarks: impl IntoIterator<Item = &'a Snark>) -> Vec<Vec<usize>> {
    snarks
        .into_iter()
        .map(|snark| {
            let accumulator_indices = &snark.protocol.accumulator_indices;
            assert!(accumulator_indices.len() <= 1, "num_proof per snark should be 1");
            if let Some(acc_indices) = accumulator_indices.last() {
                acc_indices
                    .iter()
                    .map(|&(i, j)| {
                        assert_eq!(i, 0, "accumulator should be in instance column 0");
                        j
                    })
                    .sorted()
                    .dedup()
                    .collect()
            } else {
                vec![]
            }
        })
        .collect()
}

/// Returns calldata as bytes to be sent to SNARK verifier smart contract.
/// Calldata is public instances (field elements) concatenated with proof (bytes).
/// Returned as [Bytes] for easy serialization to hex string.
#[cfg(feature = "evm")]
pub fn gen_evm_calldata_shplonk<C: CircuitExt<F>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
) -> Bytes {
    let instances = circuit.instances();
    let proof = gen_evm_proof_shplonk(params, pk, circuit, instances.clone());
    encode_calldata(&instances, &proof).into()
}

// Newtype wrapper around Base64 encoded/decoded bytes
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Base64Bytes(#[serde_as(as = "Base64")] Vec<u8>);

impl SerializeAs<Snark> for Base64Bytes {
    fn serialize_as<S>(snark: &Snark, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match bincode::serialize(snark) {
            Ok(bytes) => Base64Bytes(bytes).serialize(serializer),
            Err(e) => Err(serde::ser::Error::custom(e)),
        }
    }
}

impl<'de> DeserializeAs<'de, Snark> for Base64Bytes {
    fn deserialize_as<D>(deserializer: D) -> Result<Snark, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Base64Bytes::deserialize(deserializer)?;
        bincode::deserialize(&bytes.0).map_err(serde::de::Error::custom)
    }
}

impl SerializeAs<PlonkProtocol<G1Affine>> for Base64Bytes {
    fn serialize_as<S>(protocol: &PlonkProtocol<G1Affine>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match bincode::serialize(protocol) {
            Ok(bytes) => Base64Bytes(bytes).serialize(serializer),
            Err(e) => Err(serde::ser::Error::custom(e)),
        }
    }
}

impl<'de> DeserializeAs<'de, PlonkProtocol<G1Affine>> for Base64Bytes {
    fn deserialize_as<D>(deserializer: D) -> Result<PlonkProtocol<G1Affine>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Base64Bytes::deserialize(deserializer)?;
        bincode::deserialize(&bytes.0).map_err(serde::de::Error::custom)
    }
}

impl Hash for EnhancedSnark {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        bincode::serialize(&self.inner).unwrap().hash(state);
        self.agg_vk_hash_idx.hash(state);
    }
}

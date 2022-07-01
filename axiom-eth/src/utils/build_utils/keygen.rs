use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::Path,
};

use anyhow::Context;
use halo2_base::halo2_proofs::poly::commitment::ParamsProver;
use snark_verifier::{util::arithmetic::Domain, verifier::plonk::PlonkProtocol};
use snark_verifier_sdk::halo2::utils::{
    AggregationDependencyIntent, AggregationDependencyIntentOwned,
};

use crate::{
    halo2_base::gates::circuit::BaseCircuitParams,
    halo2_proofs::{
        plonk::{ProvingKey, VerifyingKey},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
        SerdeFormat,
    },
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    rlc::circuit::RlcCircuitParams,
    utils::keccak::decorator::RlcKeccakCircuitParams,
};

pub fn get_dummy_rlc_circuit_params(k: usize, lookup_bits: usize) -> RlcCircuitParams {
    RlcCircuitParams {
        base: BaseCircuitParams {
            k,
            lookup_bits: Some(lookup_bits),
            num_instance_columns: 1,
            ..Default::default()
        },
        num_rlc_columns: 0,
    }
}

pub fn get_dummy_rlc_keccak_params(k: usize, lookup_bits: usize) -> RlcKeccakCircuitParams {
    let rlc = get_dummy_rlc_circuit_params(k, lookup_bits);
    RlcKeccakCircuitParams { rlc, keccak_rows_per_round: 20 }
}

pub fn get_circuit_id(vk: &VerifyingKey<G1Affine>) -> String {
    let buf = vk.to_bytes(crate::halo2_proofs::SerdeFormat::RawBytes);
    format!("{}", blake3::hash(&buf))
}

/// Write vk to separate file just for ease of inspection.
pub fn write_pk_and_pinning(
    dir: &Path,
    pk: &ProvingKey<G1Affine>,
    pinning: &impl serde::Serialize,
) -> anyhow::Result<String> {
    let circuit_id = get_circuit_id(pk.get_vk());
    let pk_path = dir.join(format!("{circuit_id}.pk"));
    let vk_path = dir.join(format!("{circuit_id}.vk"));
    let pinning_path = dir.join(format!("{circuit_id}.json"));

    serde_json::to_writer_pretty(
        File::create(&pinning_path)
            .with_context(|| format!("Failed to create file {}", pinning_path.display()))?,
        pinning,
    )
    .context("Failed to serialize pinning")?;
    pk.get_vk()
        .write(
            &mut File::create(&vk_path)
                .with_context(|| format!("Failed to create file {}", vk_path.display()))?,
            SerdeFormat::RawBytes,
        )
        .context("Failed to serialize vk")?;

    let mut writer = BufWriter::with_capacity(
        128 * 1024 * 1024,
        File::create(&pk_path)
            .with_context(|| format!("Failed to create file {}", pk_path.display()))?,
    ); // 128 MB capacity
    pk.write(&mut writer, SerdeFormat::RawBytes).context("Failed to serialize pk")?;

    Ok(circuit_id)
}

pub fn read_srs_from_dir(params_dir: &Path, k: u32) -> anyhow::Result<ParamsKZG<Bn256>> {
    let srs_path = params_dir.join(format!("kzg_bn254_{k}.srs"));
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(
        File::open(srs_path.clone())
            .with_context(|| format!("Failed to read SRS from {}", srs_path.display()))?,
    ))?;
    Ok(params)
}

/// Converts `intent` into `PlonkProtocol` for pinning.
/// If `universal_agg == true`, that means this intent is going to be a dependency in a universal aggregation circuit.
/// In that case, the domain and preprocessed commitments are loaded as witnesses, so we clear them so they are not stored in the pinning.
pub fn compile_agg_dep_to_protocol(
    kzg_params: &ParamsKZG<Bn256>,
    intent: &AggregationDependencyIntentOwned,
    universal_agg: bool,
) -> PlonkProtocol<G1Affine> {
    let k = intent.vk.get_domain().k();
    // BAD UX: `compile` for `Config::kzg()` only uses `params` for `params.k()`, so we will just generate a random params with the correct `k`.
    // We provide the correct deciding key just for safety
    let dummy_params = kzg_params.from_parts(
        k,
        vec![kzg_params.get_g()[0]],
        Some(vec![]),
        kzg_params.g2(),
        kzg_params.s_g2(),
    );
    let mut protocol = AggregationDependencyIntent::from(intent).compile(&dummy_params);
    if universal_agg {
        protocol.domain = Domain::new(0, Fr::one());
        protocol.preprocessed.clear();
        protocol.transcript_initial_state = None;
    }
    protocol.domain_as_witness = None;
    protocol
}

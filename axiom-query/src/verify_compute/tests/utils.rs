use std::path::{Path, PathBuf};

use axiom_codec::{
    constants::USER_INSTANCE_COLS,
    types::native::{AxiomV2ComputeQuery, AxiomV2ComputeSnark},
    utils::native::decode_hilo_to_h256,
    HiLo,
};
use axiom_eth::{
    halo2_base::{
        gates::circuit::builder::BaseCircuitBuilder,
        halo2_proofs::{
            halo2curves::bn256::{Bn256, Fr},
            poly::{commitment::Params, kzg::commitment::ParamsKZG},
        },
    },
    halo2_proofs::{plonk::Circuit, poly::commitment::ParamsProver},
    rlc::circuit::RlcCircuitParams,
    snark_verifier::pcs::kzg::KzgDecidingKey,
    snark_verifier_sdk::{
        gen_pk,
        halo2::{gen_snark_shplonk, read_snark},
        Snark,
    },
};
use ethers_core::types::Bytes;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    components::results::types::LogicOutputResultsRoot,
    verify_compute::utils::{
        dummy_compute_circuit, get_metadata_from_protocol, get_onchain_vk_from_vk,
        write_onchain_vkey, UserCircuitParams, DEFAULT_USER_PARAMS,
    },
};

// For now we assume LogicOutputResultsRoot knows the true number of ordered subqueries
// This might change if we have multiple pages of LogicOutputResultsRoot

#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct InputVerifyCompute {
    pub source_chain_id: u64,
    pub subquery_results: LogicOutputResultsRoot,
    pub compute_query: AxiomV2ComputeQuery,
}

// We do not directly convert to CircuitInputVerifyCompute because we need
// to test the reconstruction from AxiomV2ComputeQuery back into CircuitInputVerifyCompute

/// Prepares input for `client_circuit` that is created with [BaseCircuitBuilder].
/// `client_circuit` is [BaseCircuitBuilder] populated with witnesses and fixed/copy constraints.
pub fn get_base_input(
    params: &ParamsKZG<Bn256>,
    max_outputs: usize,
    client_circuit: BaseCircuitBuilder<Fr>,
    subquery_results: LogicOutputResultsRoot,
    source_chain_id: u64,
    result_len: usize,
) -> anyhow::Result<InputVerifyCompute> {
    assert!(!client_circuit.witness_gen_only());
    let client_circuit_params = client_circuit.params();
    let pk = gen_pk(params, &client_circuit, None);
    let compute_snark = gen_snark_shplonk(params, &pk, client_circuit, None::<&str>);

    let client_metadata = get_metadata_from_protocol(
        &compute_snark.protocol,
        RlcCircuitParams { base: client_circuit_params, num_rlc_columns: 0 },
        max_outputs,
    )?;

    let onchain_vk = get_onchain_vk_from_vk(pk.get_vk(), client_metadata);
    let vkey = write_onchain_vkey(&onchain_vk)?;

    let instances = &compute_snark.instances;
    assert_eq!(instances.len(), USER_INSTANCE_COLS);
    let instances = &instances[0];
    let compute_results = instances
        .iter()
        .chunks(2)
        .into_iter()
        .take(result_len)
        .map(|hilo| {
            let hilo = hilo.collect_vec();
            assert_eq!(hilo.len(), 2);
            decode_hilo_to_h256(HiLo::from_hi_lo([*hilo[0], *hilo[1]]))
        })
        .collect();
    let compute_snark = AxiomV2ComputeSnark {
        kzg_accumulator: None,
        compute_results,
        proof_transcript: compute_snark.proof,
    };
    let compute_proof = Bytes::from(compute_snark.encode().unwrap());
    let compute_query = AxiomV2ComputeQuery {
        k: params.k() as u8,
        result_len: result_len as u16,
        vkey,
        compute_proof,
    };
    Ok(InputVerifyCompute { source_chain_id, subquery_results, compute_query })
}

/// Create a dummy snark that **will verify** successfully.
pub fn dummy_compute_snark(
    kzg_params: &ParamsKZG<Bn256>,
    user_params: UserCircuitParams,
    cache_dir: impl AsRef<Path>,
) -> Snark {
    // tag for caching the dummy
    let tag = {
        // UserCircuitParams and KzgDecidingKey are enough to tag the dummy snark; we don't need `k`
        let mut hasher = blake3::Hasher::new();
        hasher.update(&serde_json::to_vec(&user_params).unwrap());
        // hash num instance in case we change the format
        hasher.update(&user_params.num_instances().to_be_bytes());
        let dk: KzgDecidingKey<Bn256> =
            (kzg_params.get_g()[0], kzg_params.g2(), kzg_params.s_g2()).into();
        hasher.update(&serde_json::to_vec(&dk).unwrap());
        let id = hasher.finalize();
        cache_dir.as_ref().join(format!("{id}.snark"))
    };
    if let Ok(snark) = read_snark(&tag) {
        return snark;
    }
    let circuit = dummy_compute_circuit(user_params, kzg_params.k());
    let pk = gen_pk(kzg_params, &circuit, None);
    gen_snark_shplonk(kzg_params, &pk, circuit, Some(tag))
}

pub fn default_compute_snark(params: &ParamsKZG<Bn256>) -> Snark {
    let mut cache_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cache_dir.push("data");
    cache_dir.push("default_compute_snark");
    std::fs::create_dir_all(&cache_dir).unwrap();
    dummy_compute_snark(params, DEFAULT_USER_PARAMS, &cache_dir)
}

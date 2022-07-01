use std::{collections::HashMap, fs::File, marker::PhantomData};

use axiom_eth::{
    block_header::{
        get_block_header_extra_bytes_from_chain_id, get_block_header_rlp_max_lens_from_extra,
        EXTRA_DATA_INDEX,
    },
    halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr},
    halo2_proofs::plonk::Circuit,
    keccak::{promise::generate_keccak_shards_from_calls, types::ComponentTypeKeccak},
    providers::{block::get_block_rlp_from_num, setup_provider},
    utils::{
        build_utils::pinning::{CircuitPinningInstructions, Halo2CircuitPinning},
        component::{
            promise_loader::{
                comp_loader::SingleComponentLoaderParams, single::PromiseLoaderParams,
            },
            ComponentCircuit, ComponentPromiseResultsInMerkle, ComponentType,
        },
    },
};
use ethers_core::types::{Chain, H256};
use ethers_providers::Middleware;
use serde_json::{Result, Value};
use test_log::test;

use crate::components::{
    dummy_rlc_circuit_params,
    subqueries::block_header::circuit::{ComponentCircuitHeaderSubquery, CoreParamsHeaderSubquery},
};

use super::{
    types::{CircuitInputHeaderShard, CircuitInputHeaderSubquery},
    MMR_MAX_NUM_PEAKS,
};

/// Return (params, input, promise results)
fn get_test_input() -> Result<(CoreParamsHeaderSubquery, CircuitInputHeaderShard<Fr>)> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let v: Value = serde_json::from_reader(
        File::open(format!("{cargo_manifest_dir}/data/test/input_mmr_proof_for_header.json"))
            .unwrap(),
    )?;
    let historical_mmr: Vec<H256> = serde_json::from_value(v["historicalMmr"].clone())?;
    // let block_hash: H256 = serde_json::from_value(v["blockHash"].clone())?;
    // let logs_bloom: Bytes = serde_json::from_value(v["logsBloom"].clone())?;
    // dbg!(&ethers_core::utils::hex::encode(&logs_bloom[32..64]));
    let mmr_proof: Vec<H256> = serde_json::from_value(v["mmrProof"].clone())?;
    let mmr = [vec![H256::zero(); 10], historical_mmr].concat();

    let chain_id = 1;
    let block_number = 9528813;

    let max_extra_data_bytes = get_block_header_extra_bytes_from_chain_id(chain_id);
    let (header_rlp_max_bytes, _) = get_block_header_rlp_max_lens_from_extra(max_extra_data_bytes);
    let mut mmr_proof_fixed = [H256::zero(); MMR_MAX_NUM_PEAKS - 1];
    mmr_proof_fixed[..mmr_proof.len()].copy_from_slice(&mmr_proof);

    let provider = setup_provider(Chain::Mainnet);
    let mut header_rlp = get_block_rlp_from_num(&provider, block_number);
    header_rlp.resize(header_rlp_max_bytes, 0);

    let requests = vec![
        CircuitInputHeaderSubquery {
            header_rlp: header_rlp.clone(),
            mmr_proof: mmr_proof_fixed,
            field_idx: 1,
        },
        CircuitInputHeaderSubquery {
            header_rlp: header_rlp.clone(),
            mmr_proof: mmr_proof_fixed,
            field_idx: 71,
        },
        CircuitInputHeaderSubquery {
            header_rlp,
            mmr_proof: mmr_proof_fixed,
            field_idx: EXTRA_DATA_INDEX as u32,
        },
    ];
    let mut mmr_fixed = [H256::zero(); MMR_MAX_NUM_PEAKS];
    mmr_fixed[..mmr.len()].copy_from_slice(&mmr);

    Ok((
        CoreParamsHeaderSubquery { max_extra_data_bytes, capacity: requests.len() },
        CircuitInputHeaderShard::<Fr> { mmr: mmr_fixed, requests, _phantom: PhantomData },
    ))
}

#[test]
fn test_mock_header_subquery() -> anyhow::Result<()> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let k = 18;
    let (core_builder_params, input) = get_test_input().unwrap();
    let circuit_params = dummy_rlc_circuit_params(k as usize);
    let keccak_capacity = 200;
    let mut circuit = ComponentCircuitHeaderSubquery::<Fr>::new(
        core_builder_params,
        PromiseLoaderParams {
            comp_loader_params: SingleComponentLoaderParams::new(3, vec![keccak_capacity]),
        },
        circuit_params,
    );
    circuit.feed_input(Box::new(input.clone())).unwrap();

    let mut promise_results = HashMap::new();
    let promise_keccak = generate_keccak_shards_from_calls(&circuit, keccak_capacity)?;
    serde_json::to_writer(
        File::create(format!(
            "{cargo_manifest_dir}/data/test/header_promise_results_keccak_for_agg.json"
        ))?,
        &promise_keccak,
    )?;
    promise_results.insert(
        ComponentTypeKeccak::<Fr>::get_type_id(),
        ComponentPromiseResultsInMerkle::from_single_shard(promise_keccak.into_logical_results()),
    );
    circuit.calculate_params();
    circuit.fulfill_promise_results(&promise_results)?;

    let instances: Vec<Fr> = circuit.get_public_instances().into();
    MockProver::run(k as u32, &circuit, vec![instances]).unwrap().assert_satisfied();

    let comp_params = circuit.params();

    serde_json::to_writer_pretty(
        File::create(format!(
            "{cargo_manifest_dir}/configs/test/header_subquery_core_params.json"
        ))?,
        &comp_params.0,
    )?;

    serde_json::to_writer_pretty(
        File::create(format!(
            "{cargo_manifest_dir}/configs/test/header_subquery_loader_params.json"
        ))?,
        &comp_params.1,
    )?;

    serde_json::to_writer_pretty(
        File::create(format!("{cargo_manifest_dir}/data/test/input_header_for_agg.json"))?,
        &input,
    )?;
    circuit.pinning().write("configs/test/header_subquery.json")?;
    Ok(())
}

pub async fn get_latest_block_number(network: Chain) -> u64 {
    let provider = setup_provider(network);
    provider.get_block_number().await.unwrap().as_u64()
}

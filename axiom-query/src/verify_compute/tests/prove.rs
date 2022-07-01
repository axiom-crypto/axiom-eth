use std::{collections::HashMap, fs};

use axiom_codec::constants::USER_MAX_OUTPUTS;
use axiom_eth::{
    halo2_base::utils::fs::gen_srs,
    keccak::{
        promise::generate_keccak_shards_from_calls,
        types::{ComponentTypeKeccak, OutputKeccakShard},
    },
    snark_verifier_sdk::{halo2::gen_snark_shplonk, Snark},
    utils::{
        build_utils::pinning::{PinnableCircuit, RlcCircuitPinning},
        component::{
            promise_loader::single::PromiseLoaderParams, ComponentCircuit,
            ComponentPromiseResultsInMerkle, ComponentType,
        },
    },
};

use crate::{
    components::results::types::LogicOutputResultsRoot,
    verify_compute::{
        circuit::ComponentCircuitVerifyCompute,
        tests::{prepare_mock_circuit, utils::get_base_input, DUMMY_USER_K},
        utils::default_compute_circuit,
    },
};

use super::{super::types::CircuitInputVerifyCompute, InputVerifyCompute};

pub fn verify_compute_prover(
    mut logic_input: InputVerifyCompute,
    max_num_subqueries: usize,
    name: &str,
    promise_keccak: Option<OutputKeccakShard>,
    keccak_capacity: usize,
) -> anyhow::Result<(Snark, RlcCircuitPinning, OutputKeccakShard)> {
    type I = CircuitInputVerifyCompute;

    let default_params = gen_srs(DUMMY_USER_K);
    let output_results = LogicOutputResultsRoot {
        results: vec![Default::default(); max_num_subqueries],
        subquery_hashes: vec![Default::default(); max_num_subqueries],
        num_subqueries: 0,
    };
    let input = get_base_input(
        &default_params,
        USER_MAX_OUTPUTS,
        default_compute_circuit(14),
        output_results,
        0,
        0,
    )?;
    let (core_params, input) = I::reconstruct(input, &default_params)?;

    let circuit_k = 19u32;

    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    fs::create_dir_all(format!("{cargo_manifest_dir}/configs/test")).unwrap();
    fs::create_dir_all(format!("{cargo_manifest_dir}/data/test")).unwrap();
    let pinning_path = format!("{cargo_manifest_dir}/configs/test/{name}.json");
    let pk_path = format!("{cargo_manifest_dir}/data/test/{name}.pk");
    let params = gen_srs(circuit_k);

    let circuit =
        prepare_mock_circuit(core_params.clone(), circuit_k as usize, keccak_capacity, input);
    let (pk, pinning) = circuit.create_pk(&params, pk_path, pinning_path)?;

    let loader_params = PromiseLoaderParams::new_for_one_shard(keccak_capacity);
    #[cfg(all(feature = "keygen", not(debug_assertions)))]
    {
        use crate::keygen::shard::CircuitIntentVerifyCompute;
        use axiom_eth::halo2_base::utils::halo2::KeygenCircuitIntent;
        use axiom_eth::halo2_proofs::{plonk::keygen_vk, SerdeFormat};
        // check keygen
        let intent = CircuitIntentVerifyCompute {
            core_params,
            loader_params: loader_params.clone(),
            k: circuit_k,
            lookup_bits: circuit_k as usize - 1,
        };
        let circuit = intent.build_keygen_circuit();
        let vk = keygen_vk(&params, &circuit)?;
        if pk.get_vk().to_bytes(SerdeFormat::RawBytes) != vk.to_bytes(SerdeFormat::RawBytes) {
            panic!("vk mismatch");
        }
    }

    let first = logic_input.subquery_results.results[0].clone();
    logic_input.subquery_results.results.resize(max_num_subqueries, first);
    let first = logic_input.subquery_results.subquery_hashes[0];
    logic_input.subquery_results.subquery_hashes.resize(max_num_subqueries, first);
    let (core_params, input) = I::reconstruct(logic_input, &default_params)?;
    let circuit =
        ComponentCircuitVerifyCompute::prover(core_params, loader_params, pinning.clone());
    circuit.feed_input(Box::new(input)).unwrap();
    if let Some(promise_keccak) = &promise_keccak {
        assert_eq!(promise_keccak.capacity, keccak_capacity);
    }
    let promise_keccak = promise_keccak
        .unwrap_or_else(|| generate_keccak_shards_from_calls(&circuit, keccak_capacity).unwrap());
    let promise_results = HashMap::from_iter([(
        ComponentTypeKeccak::<axiom_eth::halo2curves::bn256::Fr>::get_type_id(),
        ComponentPromiseResultsInMerkle::from_single_shard(
            promise_keccak.clone().into_logical_results(),
        ),
    )]);
    circuit.fulfill_promise_results(&promise_results).unwrap();

    let snark_path = format!("{cargo_manifest_dir}/data/test/{name}.snark");
    Ok((gen_snark_shplonk(&params, &pk, circuit, Some(snark_path)), pinning, promise_keccak))
}

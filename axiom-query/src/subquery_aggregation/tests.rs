use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{Read, Write},
};

use axiom_codec::{
    constants::NUM_SUBQUERY_TYPES,
    types::native::{HeaderSubquery, SubqueryType},
};
use axiom_eth::{
    halo2_base::{
        gates::circuit::CircuitBuilderStage,
        halo2_proofs::{
            dev::MockProver,
            halo2curves::bn256::{Bn256, Fr},
            poly::kzg::commitment::ParamsKZG,
        },
        utils::fs::{gen_srs, read_params},
    },
    keccak::types::{ComponentTypeKeccak, OutputKeccakShard},
    snark_verifier_sdk::{halo2::gen_snark_shplonk, CircuitExt},
    utils::{
        build_utils::pinning::{Halo2CircuitPinning, PinnableCircuit, RlcCircuitPinning},
        component::{
            circuit::ComponentBuilder,
            promise_loader::{
                comp_loader::SingleComponentLoaderParams, multi::MultiPromiseLoaderParams,
                single::PromiseLoaderParams,
            },
            ComponentCircuit, ComponentPromiseResultsInMerkle, ComponentType,
            GroupedPromiseResults,
        },
        snark_verifier::{AggregationCircuitParams, EnhancedSnark, NUM_FE_ACCUMULATOR},
    },
};
use ethers_core::types::H256;
use test_log::test;

use crate::components::{
    results::{
        circuit::{ComponentCircuitResultsRoot, CoreParamsResultRoot},
        types::CircuitInputResultsRootShard,
    },
    subqueries::{
        block_header::{
            circuit::{
                ComponentCircuitHeaderSubquery, CoreParamsHeaderSubquery,
                PromiseLoaderHeaderSubquery,
            },
            types::{CircuitInputHeaderShard, ComponentTypeHeaderSubquery},
        },
        common::{shard_into_component_promise_results, OutputSubqueryShard},
    },
};

use super::types::{InputSubqueryAggregation, SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX};

fn generate_snark<C: CircuitExt<Fr> + PinnableCircuit<Pinning = RlcCircuitPinning>>(
    name: &'static str,
    params: &ParamsKZG<Bn256>,
    keygen_circuit: C,
    load_prover_circuit: &impl Fn(RlcCircuitPinning) -> C,
) -> anyhow::Result<EnhancedSnark> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let pinning_path = format!("{cargo_manifest_dir}/configs/test/{name}.json");
    let pk_path = format!("{cargo_manifest_dir}/data/test/{name}.pk");
    let (pk, pinning) = keygen_circuit.create_pk(params, pk_path, pinning_path)?;
    let vk = pk.get_vk();
    let mut vk_file = File::create(format!("data/test/{name}.vk"))?;
    vk.write(&mut vk_file, axiom_eth::halo2_proofs::SerdeFormat::RawBytes)?;
    let mut vk_file = File::create(format!("data/test/{name}.vk.txt"))?;
    write!(vk_file, "{:?}", vk.pinned())?;

    let component_circuit = load_prover_circuit(pinning);

    let snark_path = format!("data/test/{name}.snark");
    let snark = gen_snark_shplonk(params, &pk, component_circuit, Some(snark_path));
    Ok(EnhancedSnark { inner: snark, agg_vk_hash_idx: None })
}

fn read_header_pinning(
) -> anyhow::Result<(CoreParamsHeaderSubquery, PromiseLoaderParams, RlcCircuitPinning)> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let header_core_params: CoreParamsHeaderSubquery = serde_json::from_reader(File::open(
        format!("{cargo_manifest_dir}/configs/test/header_subquery_core_params.json"),
    )?)?;
    let header_promise_params: <PromiseLoaderHeaderSubquery<Fr> as ComponentBuilder<Fr>>::Params =
        serde_json::from_reader(File::open(format!(
            "{cargo_manifest_dir}/configs/test/header_subquery_loader_params.json"
        ))?)?;
    let header_rlc_params: RlcCircuitPinning = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/configs/test/header_subquery.json"
    ))?)?;
    Ok((header_core_params, header_promise_params, header_rlc_params))
}

fn generate_header_snark(
    params: &ParamsKZG<Bn256>,
) -> anyhow::Result<(EnhancedSnark, GroupedPromiseResults<Fr>)> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");

    let mut promise_results = HashMap::new();
    let promise_keccak: OutputKeccakShard = serde_json::from_reader(
        File::open(format!("{cargo_manifest_dir}/data/test/promise_results_keccak_for_agg.json"))
            .unwrap(),
    )?;
    let promise_header: OutputSubqueryShard<HeaderSubquery, H256> = serde_json::from_reader(
        File::open(format!("{cargo_manifest_dir}/data/test/promise_results_header_for_agg.json"))
            .unwrap(),
    )?;
    let keccak_merkle = ComponentPromiseResultsInMerkle::<Fr>::from_single_shard(
        promise_keccak.into_logical_results(),
    );
    promise_results.insert(ComponentTypeKeccak::<Fr>::get_type_id(), keccak_merkle);
    promise_results.insert(
        ComponentTypeHeaderSubquery::<Fr>::get_type_id(),
        shard_into_component_promise_results::<Fr, ComponentTypeHeaderSubquery<Fr>>(
            promise_header.convert_into(),
        ),
    );

    let header_input: CircuitInputHeaderShard<Fr> = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/data/test/input_header_for_agg.json"
    ))?)?;
    let (header_core_params, header_promise_params, header_rlc_params) = read_header_pinning()?;
    let header_circuit = ComponentCircuitHeaderSubquery::<Fr>::new(
        header_core_params.clone(),
        header_promise_params.clone(),
        header_rlc_params.params,
    );
    header_circuit.feed_input(Box::new(header_input.clone())).unwrap();
    header_circuit.fulfill_promise_results(&promise_results).unwrap();

    let header_snark =
        generate_snark("header_subquery_for_agg", params, header_circuit, &|pinning| {
            let circuit = ComponentCircuitHeaderSubquery::<Fr>::prover(
                header_core_params.clone(),
                header_promise_params.clone(),
                pinning,
            );
            circuit.feed_input(Box::new(header_input.clone())).unwrap();
            circuit.fulfill_promise_results(&promise_results).unwrap();
            circuit
        })?;
    Ok((header_snark, promise_results))
}

fn get_test_input(params: &ParamsKZG<Bn256>) -> anyhow::Result<InputSubqueryAggregation> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");

    let (header_snark, promise_results) = generate_header_snark(params)?;
    let keccak_commit =
        promise_results.get(&ComponentTypeKeccak::<Fr>::get_type_id()).unwrap().leaves()[0].commit;

    let results_input: CircuitInputResultsRootShard<Fr> = serde_json::from_reader(File::open(
        format!("{cargo_manifest_dir}/data/test/input_results_root_for_agg.json"),
    )?)?;

    let result_rlc_pinning: RlcCircuitPinning = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/configs/test/results_root_for_agg.json"
    ))?)?;

    let mut enabled_types = [false; NUM_SUBQUERY_TYPES];
    enabled_types[SubqueryType::Header as usize] = true;
    let mut params_per_comp = HashMap::new();
    params_per_comp.insert(
        ComponentTypeHeaderSubquery::<Fr>::get_type_id(),
        SingleComponentLoaderParams::new(0, vec![3]),
    );
    let promise_results_params = MultiPromiseLoaderParams { params_per_component: params_per_comp };

    let mut results_circuit = ComponentCircuitResultsRoot::<Fr>::new(
        CoreParamsResultRoot { enabled_types, capacity: results_input.subqueries.len() },
        (PromiseLoaderParams::new_for_one_shard(200), promise_results_params.clone()),
        result_rlc_pinning.params,
    );
    results_circuit.feed_input(Box::new(results_input.clone()))?;
    results_circuit.fulfill_promise_results(&promise_results).unwrap();
    results_circuit.calculate_params();

    let results_snark =
        generate_snark("results_root_for_agg", params, results_circuit, &|pinning| {
            let results_circuit = ComponentCircuitResultsRoot::<Fr>::prover(
                CoreParamsResultRoot { enabled_types, capacity: results_input.subqueries.len() },
                (PromiseLoaderParams::new_for_one_shard(200), promise_results_params.clone()),
                pinning,
            );
            results_circuit.feed_input(Box::new(results_input.clone())).unwrap();
            results_circuit.fulfill_promise_results(&promise_results).unwrap();
            results_circuit
        })?;

    Ok(InputSubqueryAggregation {
        snark_header: header_snark,
        snark_results_root: results_snark,
        snark_account: None,
        snark_storage: None,
        snark_solidity_mapping: None,
        snark_tx: None,
        snark_receipt: None,
        promise_commit_keccak: keccak_commit,
    })
}

#[test]
fn test_mock_subquery_agg() -> anyhow::Result<()> {
    let k = 19;
    let params = gen_srs(k as u32);

    let input = get_test_input(&params)?;
    let mut agg_circuit = input.build(
        CircuitBuilderStage::Mock,
        AggregationCircuitParams {
            degree: k as u32,
            num_advice: 0,
            num_lookup_advice: 0,
            num_fixed: 0,
            lookup_bits: 8,
        },
        //rlc_circuit_params.base.try_into().unwrap(),
        &params,
    )?;
    agg_circuit.calculate_params(Some(9));
    let instances = agg_circuit.instances();
    MockProver::run(k as u32, &agg_circuit, instances).unwrap().assert_satisfied();
    Ok(())
}

#[test]
#[ignore = "prover"]
fn test_generate_header_snark() -> anyhow::Result<()> {
    let k = 18;
    let params = read_params(k);
    generate_header_snark(&params)?;
    Ok(())
}

#[cfg(feature = "keygen")]
#[test]
#[ignore = "use axiom srs"]
fn test_generate_header_pk() -> anyhow::Result<()> {
    use crate::keygen::shard::ShardIntentHeader;
    use axiom_eth::halo2_base::utils::halo2::ProvingKeyGenerator;
    let k = 18;
    let params = read_params(k);
    // Generate the snark and pk using a real input
    generate_header_snark(&params)?;

    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let name = "header_subquery_for_agg";
    let pk_path = format!("{cargo_manifest_dir}/data/test/{name}.pk");
    let mut buf1 = Vec::new();
    let mut f = File::open(pk_path)?;
    f.read_to_end(&mut buf1)?;

    let (core_params, loader_params, rlc_pinning) = read_header_pinning()?;
    let intent = ShardIntentHeader {
        core_params,
        loader_params,
        k: rlc_pinning.k() as u32,
        lookup_bits: rlc_pinning.params.base.lookup_bits.unwrap_or(0),
    };
    let (pk, _) = intent.create_pk_and_pinning(&params);
    let mut buf2 = Vec::new();
    pk.write(&mut buf2, axiom_eth::halo2_proofs::SerdeFormat::RawBytesUnchecked)?;

    if buf1 != buf2 {
        panic!("proving key mismatch");
    }
    Ok(())
}

#[test]
#[ignore = "prover"]
fn test_prover_subquery_agg() -> anyhow::Result<()> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");

    let k = 20;
    let params = gen_srs(k as u32);

    let input = get_test_input(&params)?;
    let mut keygen_circuit = input.clone().build(
        CircuitBuilderStage::Keygen,
        AggregationCircuitParams { degree: k as u32, lookup_bits: k - 1, ..Default::default() },
        &params,
    )?;
    keygen_circuit.calculate_params(Some(20));
    let instance1 = keygen_circuit.instances();
    let abs_agg_vk_hash_idx = SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX + NUM_FE_ACCUMULATOR;
    let name = "subquery_aggregation_for_agg";
    let pinning_path = format!("{cargo_manifest_dir}/configs/test/{name}.json");
    let pk_path = format!("{cargo_manifest_dir}/data/test/{name}.pk");
    let (pk, pinning) = keygen_circuit.create_pk(&params, pk_path, pinning_path)?;

    #[cfg(feature = "keygen")]
    {
        // test keygen
        use axiom_eth::halo2_proofs::{plonk::keygen_vk, SerdeFormat};
        use axiom_eth::snark_verifier_sdk::{halo2::gen_dummy_snark_from_protocol, SHPLONK};
        use axiom_eth::utils::build_utils::aggregation::get_dummy_aggregation_params;
        let [dum_snark_header, dum_snark_results] =
            [&input.snark_header, &input.snark_results_root].map(|s| {
                EnhancedSnark::new(
                    gen_dummy_snark_from_protocol::<SHPLONK>(s.inner.protocol.clone()),
                    None,
                )
            });
        let input = InputSubqueryAggregation {
            snark_header: dum_snark_header,
            snark_results_root: dum_snark_results,
            snark_account: None,
            snark_storage: None,
            snark_solidity_mapping: None,
            snark_tx: None,
            snark_receipt: None,
            promise_commit_keccak: Default::default(),
        };
        let mut circuit =
            input.build(CircuitBuilderStage::Keygen, get_dummy_aggregation_params(k), &params)?;
        circuit.calculate_params(Some(20));
        let vk = keygen_vk(&params, &circuit)?;
        if pk.get_vk().to_bytes(SerdeFormat::RawBytes) != vk.to_bytes(SerdeFormat::RawBytes) {
            panic!("vk mismatch");
        }
        let instance2 = circuit.instances();
        assert_eq!(
            instance1[0][abs_agg_vk_hash_idx], instance2[0][abs_agg_vk_hash_idx],
            "agg vkey hash mismatch"
        );
    }

    let mut prover_circuit = input.build(CircuitBuilderStage::Prover, pinning.params, &params)?;
    prover_circuit.set_break_points(pinning.break_points);

    let snark = gen_snark_shplonk(&params, &pk, prover_circuit, None::<&str>);
    let instance3 = snark.instances.clone();
    let snark = EnhancedSnark {
        inner: snark,
        agg_vk_hash_idx: Some(SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX),
    };
    assert_eq!(
        instance1[0][abs_agg_vk_hash_idx], instance3[0][abs_agg_vk_hash_idx],
        "agg vkey hash mismatch"
    );

    let snark_path = format!("{cargo_manifest_dir}/data/test/{name}.snark.json");
    serde_json::to_writer(File::create(snark_path)?, &snark)?;
    Ok(())
}

use std::fs::File;

use anyhow::Result;
use axiom_eth::{
    halo2_base::{gates::circuit::CircuitBuilderStage, utils::fs::gen_srs},
    halo2curves::bn256::Fr,
    keccak::types::OutputKeccakShard,
    snark_verifier_sdk::{
        gen_pk,
        halo2::{gen_snark_shplonk, read_snark},
        CircuitExt,
    },
    utils::{
        build_utils::pinning::PinnableCircuit,
        merkle_aggregation::InputMerkleAggregation,
        snark_verifier::{AggregationCircuitParams, EnhancedSnark, NUM_FE_ACCUMULATOR},
    },
    zkevm_hashes::keccak::component::circuit::shard::{
        KeccakComponentShardCircuit, KeccakComponentShardCircuitParams,
    },
};
use itertools::Itertools;
use test_log::test;

use crate::axiom_aggregation1::types::FINAL_AGG_VKEY_HASH_IDX;

use super::types::InputAxiomAggregation1;

fn get_keccak_snark() -> Result<EnhancedSnark> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    // single shard
    let output_shard: OutputKeccakShard = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/data/test/promise_results_keccak_for_agg.json"
    ))?)?;
    let k = 18u32;
    let mut keccak_params =
        KeccakComponentShardCircuitParams::new(k as usize, 109, output_shard.capacity, false);
    keccak_params.base_circuit_params =
        KeccakComponentShardCircuit::<Fr>::calculate_base_circuit_params(&keccak_params);

    let params = gen_srs(k);
    let keygen_circuit =
        KeccakComponentShardCircuit::<Fr>::new(vec![], keccak_params.clone(), false);
    let pk = gen_pk(&params, &keygen_circuit, None);
    let break_points = keygen_circuit.base_circuit_break_points();

    let inputs = output_shard.responses.iter().map(|(k, _)| k.to_vec()).collect_vec();
    let prover_circuit = KeccakComponentShardCircuit::<Fr>::new(inputs, keccak_params, true);
    prover_circuit.set_base_circuit_break_points(break_points);
    let snark_path = format!("{cargo_manifest_dir}/data/test/keccak_shard_for_agg.snark");
    let snark = gen_snark_shplonk(&params, &pk, prover_circuit, Some(snark_path));

    let k = 20u32;
    let params = gen_srs(k);
    let agg_input = InputMerkleAggregation::new([EnhancedSnark::new(snark, None)]);

    let circuit_params =
        AggregationCircuitParams { degree: k, lookup_bits: k as usize - 1, ..Default::default() };
    let mut keygen_circuit =
        agg_input.clone().build(CircuitBuilderStage::Keygen, circuit_params, &params)?;
    keygen_circuit.calculate_params(Some(20));
    let name = "keccak_for_agg";
    let pinning_path = format!("{cargo_manifest_dir}/configs/test/{name}.json");
    let pk_path = format!("{cargo_manifest_dir}/data/test/{name}.pk");
    let snark_path = format!("{cargo_manifest_dir}/data/test/{name}.snark");
    let (pk, pinning) = keygen_circuit.create_pk(&params, pk_path, pinning_path)?;

    let prover_circuit = agg_input.prover_circuit(pinning, &params)?;
    let snark = gen_snark_shplonk(&params, &pk, prover_circuit, Some(snark_path));
    Ok(EnhancedSnark::new(snark, None))
}

fn get_test_input() -> Result<InputAxiomAggregation1> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let verify_compute_snark =
        read_snark(format!("{cargo_manifest_dir}/data/test/verify_compute_for_agg.snark"))?;
    let snark_verify_compute = EnhancedSnark::new(verify_compute_snark, None);

    let snark_subquery_agg: EnhancedSnark = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/data/test/subquery_aggregation_for_agg.snark.json"
    ))?)?;

    let snark_keccak_agg = if let Ok(snark) =
        read_snark(format!("{cargo_manifest_dir}/data/test/keccak_for_agg.snark"))
    {
        EnhancedSnark::new(snark, None)
    } else {
        get_keccak_snark()?
    };

    Ok(InputAxiomAggregation1 { snark_verify_compute, snark_subquery_agg, snark_keccak_agg })
}

#[test]
#[ignore = "prover"]
fn test_prover_axiom_agg1() -> anyhow::Result<()> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");

    let k = 22;
    let params = gen_srs(k as u32);

    let input = get_test_input()?;
    let mut keygen_circuit = input.clone().build(
        CircuitBuilderStage::Keygen,
        AggregationCircuitParams { degree: k as u32, lookup_bits: k - 1, ..Default::default() },
        &params,
    )?;
    keygen_circuit.calculate_params(Some(20));
    let instance1 = keygen_circuit.instances();
    let abs_agg_vk_hash_idx = NUM_FE_ACCUMULATOR + FINAL_AGG_VKEY_HASH_IDX;
    let name = "axiom_aggregation1_for_agg";
    let pinning_path = format!("{cargo_manifest_dir}/configs/test/{name}.json");
    let pk_path = format!("{cargo_manifest_dir}/data/test/{name}.pk");
    let (pk, pinning) = keygen_circuit.create_pk(&params, pk_path, pinning_path)?;
    keygen_circuit.builder.clear();
    drop(keygen_circuit);

    #[cfg(all(feature = "keygen", not(debug_assertions)))]
    {
        // test keygen
        use crate::subquery_aggregation::types::SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX;
        use axiom_eth::halo2_proofs::{plonk::keygen_vk, SerdeFormat};
        use axiom_eth::snark_verifier_sdk::{halo2::gen_dummy_snark_from_protocol, SHPLONK};
        use axiom_eth::utils::build_utils::aggregation::get_dummy_aggregation_params;
        let [dum_snark_verify_comp, mut dum_snark_sub_agg, dum_snark_keccak] =
            [&input.snark_verify_compute, &input.snark_subquery_agg, &input.snark_keccak_agg]
                .map(|s| gen_dummy_snark_from_protocol::<SHPLONK>(s.inner.protocol.clone()));
        let subquery_abs_agg_vk_hash_idx =
            NUM_FE_ACCUMULATOR + SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX;
        // The correct one from the subquery agg circuit
        let subquery_agg_vk_hash =
            input.snark_subquery_agg.inner.instances[0][subquery_abs_agg_vk_hash_idx];
        // Put correct one into the dummy
        dum_snark_sub_agg.instances[0][subquery_abs_agg_vk_hash_idx] = subquery_agg_vk_hash;
        let input = InputAxiomAggregation1 {
            snark_verify_compute: EnhancedSnark::new(dum_snark_verify_comp, None),
            snark_subquery_agg: EnhancedSnark::new(
                dum_snark_sub_agg,
                Some(SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX),
            ),
            snark_keccak_agg: EnhancedSnark::new(dum_snark_keccak, None),
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
    let instance3 = prover_circuit.instances();
    assert_eq!(
        instance1[0][abs_agg_vk_hash_idx], instance3[0][abs_agg_vk_hash_idx],
        "agg vkey hash mismatch"
    );

    let snark = gen_snark_shplonk(&params, &pk, prover_circuit, None::<&str>);
    let snark = EnhancedSnark { inner: snark, agg_vk_hash_idx: Some(FINAL_AGG_VKEY_HASH_IDX) };

    let snark_path = format!("{cargo_manifest_dir}/data/test/{name}.snark.json");
    serde_json::to_writer(File::create(snark_path)?, &snark)?;
    Ok(())
}

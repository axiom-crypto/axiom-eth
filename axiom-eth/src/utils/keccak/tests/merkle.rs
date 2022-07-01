use std::{
    fs::{remove_file, File},
    ops::Deref,
    path::Path,
    sync::Arc,
};

use halo2_base::{
    gates::flex_gate::MultiPhaseThreadBreakPoints,
    halo2_proofs::{halo2curves::bn256::Fr, plonk::keygen_vk_custom, SerdeFormat},
    utils::halo2::ProvingKeyGenerator,
};
use itertools::Itertools;
use snark_verifier_sdk::{halo2::utils::AggregationDependencyIntentOwned, read_pk};
use zkevm_hashes::keccak::component::circuit::shard::{
    KeccakComponentShardCircuit, KeccakComponentShardCircuitParams,
};

use crate::{
    halo2_base::{gates::circuit::CircuitBuilderStage, utils::fs::gen_srs},
    snark_verifier_sdk::{halo2::gen_snark_shplonk, LIMBS},
    utils::{
        build_utils::{
            aggregation::get_dummy_aggregation_params,
            pinning::{aggregation::AggTreeId, PinnableCircuit},
        },
        component::utils::compute_poseidon,
        merkle_aggregation::{keygen::AggIntentMerkle, InputMerkleAggregation},
    },
};

use super::shard::get_test_keccak_shard_snark;

#[test]
#[ignore = "prover"]
pub fn test_keccak_merkle_aggregation_prover() -> anyhow::Result<()> {
    let dummy_snark = get_test_keccak_shard_snark(vec![])?;
    let inputs = vec![
        (0u8..200).collect_vec(),
        vec![],
        (0u8..1).collect_vec(),
        (0u8..135).collect_vec(),
        (0u8..136).collect_vec(),
        (0u8..200).collect_vec(),
    ];
    let snark = get_test_keccak_shard_snark(inputs)?;
    let commit = snark.inner.instances[0][0];
    let k = 20u32;
    let params = gen_srs(k);
    let [dummy_snarks, snarks] =
        [dummy_snark, snark].map(|s| InputMerkleAggregation::new(vec![s; 2]));

    let circuit_params = get_dummy_aggregation_params(k as usize);
    let mut keygen_circuit =
        dummy_snarks.build(CircuitBuilderStage::Keygen, circuit_params, &params)?;
    keygen_circuit.calculate_params(Some(20));
    let pinning_path = "configs/tests/keccak_shard2_merkle.json";
    let pk_path = "data/tests/keccak_shard2_merkle.pk";
    let (pk, pinning) = keygen_circuit.create_pk(&params, pk_path, pinning_path)?;

    let prover_circuit = snarks.prover_circuit(pinning, &params)?;
    let snark = gen_snark_shplonk(&params, &pk, prover_circuit, None::<&str>);
    let root = snark.instances[0][4 * LIMBS];
    assert_eq!(compute_poseidon(&[commit, commit]), root);

    remove_file(pk_path).ok();
    remove_file("data/test/keccak_shard.pk").ok();
    Ok(())
}

// CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false cargo t test_keygen_merkle_aggregation -- --nocapture
#[test]
#[ignore = "keygen; turn off debug assertions"]
fn test_keygen_merkle_aggregation() -> anyhow::Result<()> {
    let dummy_snark = get_test_keccak_shard_snark(vec![])?;
    let pk_path = Path::new("data/tests/keccak_shard.pk");
    let pinning_path = "configs/tests/keccak_shard.json";
    let (params, _): (KeccakComponentShardCircuitParams, MultiPhaseThreadBreakPoints) =
        serde_json::from_reader(File::open(pinning_path)?)?;
    let dep_pk = read_pk::<KeccakComponentShardCircuit<Fr>>(pk_path, params).unwrap();
    let dep_vk = dep_pk.get_vk().clone();

    let dep_intent = AggregationDependencyIntentOwned {
        vk: dep_vk,
        num_instance: vec![1],
        accumulator_indices: None,
        agg_vk_hash_data: None,
    };
    let k = 20;
    let kzg_params = gen_srs(k);
    let kzg_params = Arc::new(kzg_params);
    let child_id = AggTreeId::default();
    let intent = AggIntentMerkle {
        kzg_params: kzg_params.clone(),
        to_agg: vec![child_id; 2],
        deps: vec![dep_intent; 2],
        k,
    };
    let (pk1, _) = intent.create_pk_and_pinning(&kzg_params);

    let dummy_snarks = InputMerkleAggregation::new(vec![dummy_snark; 2]);
    let circuit_params = get_dummy_aggregation_params(k as usize);
    let mut keygen_circuit =
        dummy_snarks.build(CircuitBuilderStage::Keygen, circuit_params, &kzg_params)?;
    keygen_circuit.calculate_params(Some(20));
    let vk2 = keygen_vk_custom(kzg_params.deref(), &keygen_circuit, false)?;

    let mut buf1 = Vec::new();
    pk1.get_vk().write(&mut buf1, SerdeFormat::RawBytesUnchecked)?;
    let mut buf2 = Vec::new();
    vk2.write(&mut buf2, SerdeFormat::RawBytesUnchecked)?;
    if buf1 != buf2 {
        panic!("vkey mismatch");
    }

    Ok(())
}

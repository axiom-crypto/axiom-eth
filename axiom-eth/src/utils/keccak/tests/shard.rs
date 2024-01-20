use std::{
    fs::{remove_file, File},
    path::Path,
};

use halo2_base::{gates::flex_gate::MultiPhaseThreadBreakPoints, halo2_proofs::plonk::Circuit};
use itertools::Itertools;
use snark_verifier_sdk::{gen_pk, read_pk};
use zkevm_hashes::keccak::component::circuit::shard::{
    KeccakComponentShardCircuit, KeccakComponentShardCircuitParams,
};

use crate::{
    halo2_base::utils::fs::gen_srs,
    halo2curves::bn256::Fr,
    snark_verifier_sdk::halo2::gen_snark_shplonk,
    utils::{keccak::get_keccak_unusable_rows, snark_verifier::EnhancedSnark},
};

pub fn get_test_keccak_shard_snark(mult_inputs: Vec<Vec<u8>>) -> anyhow::Result<EnhancedSnark> {
    let k = 18u32;
    let capacity = 50;
    let rows_per_round = 20;
    let num_unusable_rows = get_keccak_unusable_rows(rows_per_round);
    let mut keccak_params =
        KeccakComponentShardCircuitParams::new(k as usize, num_unusable_rows, capacity, false);
    let base_params =
        KeccakComponentShardCircuit::<Fr>::calculate_base_circuit_params(&keccak_params);
    keccak_params.base_circuit_params = base_params;

    let params = gen_srs(k);
    let pk_path = Path::new("data/tests/keccak_shard.pk");
    let pinning_path = "configs/tests/keccak_shard.json";
    let (pk, pinning) = if let Ok(pk) =
        read_pk::<KeccakComponentShardCircuit<Fr>>(pk_path, keccak_params.clone())
    {
        let pinning: (KeccakComponentShardCircuitParams, MultiPhaseThreadBreakPoints) =
            serde_json::from_reader(File::open(pinning_path)?)?;
        (pk, pinning)
    } else {
        let circuit = KeccakComponentShardCircuit::<Fr>::new(vec![], keccak_params, false);
        let pk = gen_pk(&params, &circuit, Some(pk_path));
        let break_points = circuit.base_circuit_break_points();
        let pinning = (circuit.params(), break_points);
        serde_json::to_writer_pretty(File::create(pinning_path)?, &pinning)?;
        (pk, pinning)
    };

    let prover_circuit = KeccakComponentShardCircuit::<Fr>::new(mult_inputs, pinning.0, true);
    prover_circuit.set_base_circuit_break_points(pinning.1);
    let snark = gen_snark_shplonk(&params, &pk, prover_circuit, None::<&str>);
    Ok(EnhancedSnark { inner: snark, agg_vk_hash_idx: None })
}

#[test]
#[ignore = "prover"]
pub fn test_keccak_shard_prover() {
    let inputs = vec![
        (0u8..200).collect_vec(),
        vec![],
        (0u8..1).collect_vec(),
        (0u8..135).collect_vec(),
        (0u8..136).collect_vec(),
        (0u8..200).collect_vec(),
    ];
    get_test_keccak_shard_snark(inputs).unwrap();
    remove_file("data/test/keccak_shard.pk").ok();
}

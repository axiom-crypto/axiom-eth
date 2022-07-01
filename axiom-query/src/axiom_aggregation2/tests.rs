use std::{fs::File, io::Write, path::Path, str::FromStr};

use anyhow::Result;
use axiom_eth::{
    halo2_base::{gates::circuit::CircuitBuilderStage, utils::fs::gen_srs},
    halo2_proofs::dev::MockProver,
    snark_verifier_sdk::{
        evm::{encode_calldata, gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
        halo2::aggregation::AggregationCircuit,
        CircuitExt,
    },
    utils::{
        build_utils::pinning::PinnableCircuit,
        snark_verifier::{AggregationCircuitParams, EnhancedSnark, NUM_FE_ACCUMULATOR},
    },
};
use ethers_core::types::Address;
use hex::encode;

use crate::axiom_aggregation1::types::FINAL_AGG_VKEY_HASH_IDX;

use super::circuit::InputAxiomAggregation2;

fn get_test_input() -> Result<InputAxiomAggregation2> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let snark_axiom_agg1: EnhancedSnark = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/data/test/axiom_aggregation1_for_agg.snark.json"
    ))?)?;

    Ok(InputAxiomAggregation2 {
        snark_axiom_agg1,
        payee: Address::from_str("0x00000000000000000000000000000000deadbeef")?,
    })
}

#[test]
#[ignore = "requires real SRS"]
fn test_mock_axiom_agg2() -> anyhow::Result<()> {
    let k = 22;
    let params = gen_srs(k as u32);

    let input = get_test_input()?;
    let mut circuit = input.build(
        CircuitBuilderStage::Mock,
        AggregationCircuitParams { degree: k as u32, lookup_bits: k - 1, ..Default::default() },
        &params,
    )?;
    circuit.calculate_params(Some(20));
    let instances = circuit.instances();
    MockProver::run(k as u32, &circuit, instances).unwrap().assert_satisfied();

    Ok(())
}

// cargo t test_prover_axiom_agg2 --features revm -- --ignored --nocapture
// feature "revm" requires solc 0.8.19 installed
#[test]
#[ignore = "prover"]
fn test_prover_axiom_agg2() -> anyhow::Result<()> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");

    let k = 23;
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
    let name = "axiom_aggregation2";
    let pinning_path = format!("{cargo_manifest_dir}/configs/test/{name}.json");
    let pk_path = format!("{cargo_manifest_dir}/data/test/{name}.pk");
    let (pk, pinning) = keygen_circuit.create_pk(&params, pk_path, pinning_path)?;
    keygen_circuit.builder.clear();
    drop(keygen_circuit);

    #[cfg(all(feature = "keygen", not(debug_assertions)))]
    {
        // test keygen
        use axiom_eth::halo2_proofs::{plonk::keygen_vk, SerdeFormat};
        use axiom_eth::snark_verifier_sdk::{halo2::gen_dummy_snark_from_protocol, SHPLONK};
        use axiom_eth::utils::build_utils::aggregation::get_dummy_aggregation_params;
        let mut dum_snark_axiom_agg1 =
            gen_dummy_snark_from_protocol::<SHPLONK>(input.snark_axiom_agg1.inner.protocol.clone());
        // The correct one from the subquery agg circuit
        let axiom_agg1_agg_vk_hash = input.snark_axiom_agg1.inner.instances[0][abs_agg_vk_hash_idx];
        // Put correct one into the dummy
        dum_snark_axiom_agg1.instances[0][abs_agg_vk_hash_idx] = axiom_agg1_agg_vk_hash;
        let input = InputAxiomAggregation2 {
            snark_axiom_agg1: EnhancedSnark::new(
                dum_snark_axiom_agg1,
                Some(FINAL_AGG_VKEY_HASH_IDX),
            ),
            payee: Default::default(),
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

    let sol_path = format!("{cargo_manifest_dir}/data/test/{name}.sol");
    let _solidity_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
        &params,
        pk.get_vk(),
        prover_circuit.num_instance(),
        Some(Path::new(&sol_path)),
    );
    let instances = prover_circuit.instances();
    let proof = gen_evm_proof_shplonk(&params, &pk, prover_circuit, instances.clone());
    let evm_proof = encode(encode_calldata(&instances, &proof));
    let mut f = File::create(format!("{cargo_manifest_dir}/data/test/{name}.evm_proof"))?;
    write!(f, "{evm_proof}")?;
    #[cfg(feature = "revm")]
    axiom_eth::snark_verifier_sdk::evm::evm_verify(_solidity_code, instances, proof);

    Ok(())
}

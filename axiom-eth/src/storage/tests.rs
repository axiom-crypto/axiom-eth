use super::{circuit::EthBlockStorageCircuit, *};
use crate::{
    providers::setup_provider,
    rlc::{circuit::RlcCircuitParams, tests::get_rlc_params},
    utils::eth_circuit::{create_circuit, EthCircuitParams},
};
use ark_std::{end_timer, start_timer};
use ethers_core::{
    types::{Address, H256},
    utils::keccak256,
};
use halo2_base::{
    gates::circuit::BaseCircuitParams,
    utils::{
        fs::gen_srs,
        testing::{check_proof_with_instances, gen_proof_with_instances},
    },
};
use halo2_base::{
    gates::circuit::CircuitBuilderStage,
    halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, plonk::*},
};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Write};
use test_log::test;

fn get_test_circuit(network: Chain, num_slots: usize) -> EthBlockStorageCircuit<Fr> {
    let provider = setup_provider(network);
    let addr;
    let block_number;
    match network {
        Chain::Mainnet => {
            // cryptopunks
            addr = "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB".parse::<Address>().unwrap();
            block_number = 16356350;
            //block_number = 0xf929e6;
        }
        Chain::Goerli => {
            addr = "0xf2d1f94310823fe26cfa9c9b6fd152834b8e7849".parse::<Address>().unwrap();
            block_number = 0x713d54;
        }
        _ => {
            todo!()
        }
    }
    // For only occupied slots:
    let slot_nums = [0u64, 1u64, 2u64, 3u64, 6u64, 8u64];
    let mut slots = vec![];
    slots.extend(slot_nums.iter().map(|x| H256::from_low_u64_be(*x)));
    slots.extend((0..num_slots.saturating_sub(slot_nums.len())).map(|x| {
        let mut bytes = [0u8; 64];
        bytes[31] = x as u8;
        bytes[63] = 10;
        H256::from_slice(&keccak256(bytes))
    }));
    slots.truncate(num_slots);
    EthBlockStorageCircuit::from_provider(&provider, block_number, addr, slots, 13, 13, network)
}

#[test]
pub fn test_mock_single_eip1186() {
    let params = get_rlc_params("configs/tests/storage.json");
    let k = params.base.k as u32;

    let input = get_test_circuit(Chain::Mainnet, 1);
    let mut circuit = create_circuit(CircuitBuilderStage::Mock, params, input);
    circuit.mock_fulfill_keccak_promises(None);
    circuit.calculate_params();
    let instances = circuit.instances();
    MockProver::run(k, &circuit, instances).unwrap().assert_satisfied();
}

fn get_test_circuit_detailed_tether(
    network: Chain,
    slot_nums: Vec<H256>,
) -> EthBlockStorageCircuit<Fr> {
    assert!(slot_nums.len() <= 10);
    let provider = setup_provider(network);
    let addr;
    let block_number;
    match network {
        Chain::Mainnet => {
            addr = "0xdAC17F958D2ee523a2206206994597C13D831ec7".parse::<Address>().unwrap();
            block_number = 16799999;
        }
        Chain::Goerli => {
            addr = "0xdAC17F958D2ee523a2206206994597C13D831ec7".parse::<Address>().unwrap();
            block_number = 16799999;
        }
        _ => todo!(),
    }
    // For only occupied slots:
    let slots = slot_nums;
    EthBlockStorageCircuit::from_provider(&provider, block_number, addr, slots, 8, 9, network)
}

#[test]
pub fn test_mock_small_val() {
    let params = get_rlc_params("configs/tests/storage.json");
    let k = params.base.k as u32;
    let lower: u128 = 0xdfad11d8b97bedfbd5b2574864aec982;
    let upper: u128 = 0x015130eac76c1a0c44f4cd1dcd859cd8;
    let mut bytes: [u8; 32] = [0; 32];
    bytes[..16].copy_from_slice(&upper.to_be_bytes());
    bytes[16..].copy_from_slice(&lower.to_be_bytes());
    let slot = H256(bytes);
    let input = get_test_circuit_detailed_tether(Chain::Mainnet, vec![slot]);
    let mut circuit = create_circuit(CircuitBuilderStage::Mock, params, input);
    circuit.mock_fulfill_keccak_promises(None);
    circuit.calculate_params();
    let instances = circuit.instances();
    MockProver::run(k, &circuit, instances).unwrap().assert_satisfied();
}

#[derive(Serialize, Deserialize)]
struct BenchParams(RlcCircuitParams, usize); // (params, num_slots)

#[test]
#[ignore = "bench"]
pub fn bench_eip1186() -> Result<(), Box<dyn std::error::Error>> {
    let bench_params_file = File::create("configs/bench/storage.json").unwrap();
    std::fs::create_dir_all("data/bench")?;
    let mut fs_results = File::create("data/bench/storage.csv").unwrap();
    writeln!(fs_results, "degree,num_slots,total_advice,num_rlc_columns,num_advice,num_lookup,num_fixed,proof_time,verify_time")?;

    let mut all_bench_params = vec![];
    let bench_k_num = vec![(15, 1), (18, 10), (20, 32)];
    for (k, num_slots) in bench_k_num {
        println!("---------------------- degree = {k} ------------------------------",);
        let input = get_test_circuit(Chain::Mainnet, num_slots);
        let mut dummy_params = EthCircuitParams::default().rlc;
        dummy_params.base.k = k;
        let mut circuit = create_circuit(CircuitBuilderStage::Keygen, dummy_params, input.clone());
        circuit.mock_fulfill_keccak_promises(None);
        circuit.calculate_params();

        let params = gen_srs(k as u32);
        let vk = keygen_vk(&params, &circuit)?;
        let pk = keygen_pk(&params, vk, &circuit)?;
        let bench_params = circuit.params().rlc;
        let break_points = circuit.break_points();

        // create a proof
        let proof_time = start_timer!(|| "create proof SHPLONK");
        let phase0_time = start_timer!(|| "phase 0 synthesize");
        let circuit = create_circuit(CircuitBuilderStage::Prover, bench_params.clone(), input)
            .use_break_points(break_points);
        circuit.mock_fulfill_keccak_promises(None);
        let instances = circuit.instances();
        let instances = instances.iter().map(|x| &x[..]).collect_vec();
        end_timer!(phase0_time);
        let proof = gen_proof_with_instances(&params, &pk, circuit, &instances);
        end_timer!(proof_time);

        let verify_time = start_timer!(|| "Verify time");
        check_proof_with_instances(&params, pk.get_vk(), &proof, &instances, true);
        end_timer!(verify_time);

        let RlcCircuitParams {
            base:
                BaseCircuitParams {
                    k,
                    num_advice_per_phase,
                    num_fixed,
                    num_lookup_advice_per_phase,
                    ..
                },
            num_rlc_columns,
        } = bench_params.clone();
        writeln!(
            fs_results,
            "{},{},{},{},{:?},{:?},{},{:.2}s,{:?}",
            k,
            num_slots,
            num_rlc_columns
                + num_advice_per_phase.iter().sum::<usize>()
                + num_lookup_advice_per_phase.iter().sum::<usize>(),
            num_rlc_columns,
            num_advice_per_phase,
            num_lookup_advice_per_phase,
            num_fixed,
            proof_time.time.elapsed().as_secs_f64(),
            verify_time.time.elapsed()
        )
        .unwrap();
        all_bench_params.push(BenchParams(bench_params, num_slots));
    }
    serde_json::to_writer_pretty(bench_params_file, &all_bench_params).unwrap();
    Ok(())
}

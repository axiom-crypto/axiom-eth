use std::{
    fs::File,
    path::{Path, PathBuf},
};

use axiom_eth::{
    block_header::get_block_header_extra_bytes,
    halo2_base::{gates::circuit::CircuitBuilderStage, utils::fs::gen_srs},
    halo2_proofs::plonk::Circuit,
    halo2curves::bn256::Fr,
    providers::{
        block::{get_block_rlp, get_blocks},
        setup_provider,
    },
    rlc::virtual_region::RlcThreadBreakPoints,
    snark_verifier_sdk::{
        evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
        gen_pk,
        halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
        read_pk, CircuitExt, Snark,
    },
    utils::{
        build_utils::pinning::{aggregation::AggregationCircuitPinning, Halo2CircuitPinning},
        get_merkle_mountain_range,
        keccak::decorator::RlcKeccakCircuitParams,
        merkle_aggregation::InputMerkleAggregation,
        snark_verifier::{EnhancedSnark, NUM_FE_ACCUMULATOR},
        DEFAULT_RLC_CACHE_BITS,
    },
};
use ethers_core::types::Chain;
use itertools::Itertools;
use serde::{de::DeserializeOwned, Serialize};
use test_log::test;

use crate::{
    aggregation::{
        final_merkle::{
            EthBlockHeaderChainRootAggregationCircuit, EthBlockHeaderChainRootAggregationInput,
        },
        intermediate::EthBlockHeaderChainIntermediateAggregationInput,
    },
    header_chain::{EthBlockHeaderChainCircuit, EthBlockHeaderChainInput},
};

use super::chain_instance::EthBlockHeaderChainInstance;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Finality {
    /// Produces as many snarks as needed to fit the entire block number range, without any final processing.
    None,
    /// The block number range must fit within the specified max depth.
    /// Produces a single final snark with the starting & ending block numbers, previous and last block hashes,
    /// and merkle mountain range as output.
    Root,
    /// The block number range must fit within the specified max depth. `Evm(round)` performs `round + 1`
    /// rounds of SNARK verification on the final `Merkle` circuit
    Evm(usize),
}

fn fname(network: Chain, initial_depth: usize, depth: usize, finality: Finality) -> String {
    let prefix = if depth == initial_depth {
        format!("{}_{}", network, depth)
    } else {
        format!("{}_{}_{}", network, depth, initial_depth)
    };
    let suffix = match finality {
        Finality::None => "".to_string(),
        Finality::Root => "_root".to_string(),
        Finality::Evm(round) => format!("_for_evm_{round}"),
    };
    format!("{}{}", prefix, suffix)
}

fn read_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> T {
    serde_json::from_reader(File::open(path).unwrap()).unwrap()
}
fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) {
    serde_json::to_writer_pretty(File::create(path).unwrap(), value).unwrap();
}

type KeccakPinning = (RlcKeccakCircuitParams, RlcThreadBreakPoints);

/// Does binary tree aggregation with leaf circuit EthBlockHeaderChainCircuit of depth `initial_depth`.
/// aggregates intermediate layers up to depth `max_depth`. For the root aggregation of depth `max_depth`
/// it will either use EthBlockHeaderIntermediateAggregationCircuit if finality is None, or else
/// EthBlockHeaderRootAggregationCircuit.
/// If finality is `Evm(round)`, then it will perform `round + 1` rounds of passthrough SNARK verification
/// using MerkleAggregationCircuit (with a single snark  there is no merklelization, it is just passthrough).
///
/// Proof will be for blocks [start_num, stop_num)
pub fn header_tree_aggregation(
    network: Chain,
    start_num: usize,
    stop_num: usize,
    initial_depth: usize,
    max_depth: usize,
    finality: Finality,
) {
    // ===== Initial leaf layer ====
    // get RLP encoded headers
    let provider = setup_provider(network);
    let blocks = get_blocks(&provider, start_num as u64..stop_num as u64).unwrap();
    let header_rlp_encodings =
        blocks.iter().map(|block| get_block_rlp(block.as_ref().unwrap())).collect_vec();

    // create pkey
    let name = fname(network, initial_depth, initial_depth, Finality::None);
    let pk_path = PathBuf::from(format!("data/tests/{}.pk", &name));
    let pinning_path = format!("configs/tests/{}.json", &name);
    let header_extra_bytes = get_block_header_extra_bytes(network);
    let pinning: KeccakPinning = read_json(&pinning_path);

    let params = gen_srs(pinning.0.k() as u32);
    let (pk, pinning) =
        if let Ok(pk) = read_pk::<EthBlockHeaderChainCircuit<Fr>>(&pk_path, pinning.0.clone()) {
            (pk, pinning)
        } else {
            let first_rlp = header_rlp_encodings[0].clone();
            let input = EthBlockHeaderChainInput::<Fr>::new(
                vec![first_rlp],
                1,
                initial_depth,
                header_extra_bytes,
            );
            let mut circuit = EthBlockHeaderChainCircuit::new_impl(
                CircuitBuilderStage::Keygen,
                input,
                pinning.0,
                DEFAULT_RLC_CACHE_BITS,
            );
            circuit.calculate_params();
            let pk = gen_pk(&params, &circuit, Some(&pk_path));
            let pinning = (circuit.params(), circuit.break_points());
            write_json(pinning_path, &pinning);
            (pk, pinning)
        };
    let mut snarks: Vec<Snark> = vec![];
    for start in (start_num..stop_num).step_by(1 << initial_depth) {
        let stop = std::cmp::min(start + (1 << initial_depth), stop_num) as usize;
        let rlps = header_rlp_encodings[start - start_num..stop - start_num].to_vec();
        let input = EthBlockHeaderChainInput::<Fr>::new(
            rlps,
            (stop - start) as u32,
            initial_depth,
            header_extra_bytes,
        );
        let circuit = EthBlockHeaderChainCircuit::new_impl(
            CircuitBuilderStage::Prover,
            input,
            pinning.0.clone(),
            DEFAULT_RLC_CACHE_BITS,
        )
        .use_break_points(pinning.1.clone());
        let snark_path = format!("data/tests/{}_{}_{}.snark", &name, start, stop);
        let snark = gen_snark_shplonk(&params, &pk, circuit, Some(snark_path));
        snarks.push(snark);
    }
    drop(params);
    drop(pk);

    // ====== Intermediate layers ======
    let mut last_inter_depth = max_depth - 1;
    if finality == Finality::None {
        last_inter_depth += 1;
    }
    for depth in initial_depth + 1..=last_inter_depth {
        let prev_snarks = std::mem::take(&mut snarks);
        let mut start = start_num;

        let name = fname(network, initial_depth, depth, Finality::None);
        let pk_path = PathBuf::from(format!("data/tests/{}.pk", &name));
        let pinning_path = format!("configs/tests/{}.json", &name);
        let pinning: AggregationCircuitPinning = read_json(&pinning_path);
        let params = gen_srs(pinning.params.degree);
        let (pk, pinning) = if let Ok(pk) = read_pk::<AggregationCircuit>(&pk_path, pinning.params)
        {
            (pk, pinning)
        } else {
            let stop = std::cmp::min(start + (1 << (depth - 1)), stop_num);
            let input = EthBlockHeaderChainIntermediateAggregationInput::new(
                vec![prev_snarks[0].clone(), prev_snarks[0].clone()],
                (stop - start) as u32,
                depth,
                initial_depth,
            );
            let mut circuit =
                input.build(CircuitBuilderStage::Keygen, pinning.params, &params).unwrap().0;
            circuit.calculate_params(Some(9));
            let pk = gen_pk(&params, &circuit, Some(&pk_path));
            let pinning = AggregationCircuitPinning::new(circuit.params(), circuit.break_points());
            write_json(pinning_path, &pinning);
            (pk, pinning)
        };
        for snark_pair in prev_snarks.into_iter().chunks(2).into_iter() {
            let mut snark_pair = snark_pair.collect_vec();
            if snark_pair.len() == 1 {
                let first = snark_pair[0].clone();
                snark_pair.push(first);
            }
            let stop = std::cmp::min(start + (1 << depth), stop_num);
            let input = EthBlockHeaderChainIntermediateAggregationInput::new(
                snark_pair,
                (stop - start) as u32,
                depth,
                initial_depth,
            );
            let circuit = input
                .build(CircuitBuilderStage::Prover, pinning.params, &params)
                .unwrap()
                .0
                .use_break_points(pinning.break_points.clone());
            let snark_path = format!("data/tests/{}_{}_{}.snark", &name, start, stop);
            let snark = gen_snark_shplonk(&params, &pk, circuit, Some(snark_path));
            snarks.push(snark);
            start = stop;
        }
    }
    if finality == Finality::None {
        return;
    }
    // ==== Root layer ====
    let depth = max_depth;
    let prev_snarks = std::mem::take(&mut snarks);
    let mut start = start_num;

    let name = fname(network, initial_depth, depth, Finality::Root);
    let pk_path = PathBuf::from(format!("data/tests/{}.pk", &name));
    let pinning_path = format!("configs/tests/{}.json", &name);
    let pinning: KeccakPinning = read_json(&pinning_path);
    let params = gen_srs(pinning.0.k() as u32);
    let (pk, pinning) = if let Ok(pk) =
        read_pk::<EthBlockHeaderChainRootAggregationCircuit>(&pk_path, pinning.0.clone())
    {
        (pk, pinning)
    } else {
        let stop = std::cmp::min(start + (1 << (depth - 1)), stop_num);
        let input = EthBlockHeaderChainRootAggregationInput::new(
            vec![prev_snarks[0].clone(), prev_snarks[0].clone()],
            (stop - start) as u32,
            depth,
            initial_depth,
            &params,
        )
        .unwrap();
        let mut circuit = EthBlockHeaderChainRootAggregationCircuit::new_impl(
            CircuitBuilderStage::Keygen,
            input,
            pinning.0.clone(),
            0, // note: rlc is not used
        );
        circuit.calculate_params();
        let pk = gen_pk(&params, &circuit, Some(&pk_path));
        let pinning = (circuit.params(), circuit.break_points());
        write_json(pinning_path, &pinning);
        (pk, pinning)
    };
    for snark_pair in prev_snarks.into_iter().chunks(2).into_iter() {
        let mut snark_pair = snark_pair.collect_vec();
        if snark_pair.len() == 1 {
            let first = snark_pair[0].clone();
            snark_pair.push(first);
        }
        let stop = std::cmp::min(start + (1 << depth), stop_num);
        let input = EthBlockHeaderChainRootAggregationInput::new(
            snark_pair,
            (stop - start) as u32,
            depth,
            initial_depth,
            &params,
        )
        .unwrap();
        let circuit = EthBlockHeaderChainRootAggregationCircuit::new_impl(
            CircuitBuilderStage::Prover,
            input,
            pinning.0.clone(),
            0, // note: rlc is not used
        )
        .use_break_points(pinning.1.clone());
        let snark_path = format!("data/tests/{}_{}_{}.snark", &name, start, stop);
        let snark = gen_snark_shplonk(&params, &pk, circuit, Some(snark_path));
        snarks.push(snark);
        start = stop;
    }
    drop(params);
    drop(pk);
    // ==== Passthrough verification to shrink snark size ====
    let mut final_instances = vec![];
    if let Finality::Evm(round) = finality {
        for r in 0..=round {
            let name = fname(network, initial_depth, depth, Finality::Evm(r));
            let pk_path = PathBuf::from(format!("data/tests/{}.pk", &name));
            let pinning_path = format!("configs/tests/{}.json", &name);
            let pinning: AggregationCircuitPinning = read_json(&pinning_path);
            let params = gen_srs(pinning.params.degree);
            let (pk, pinning) =
                if let Ok(pk) = read_pk::<AggregationCircuit>(&pk_path, pinning.params) {
                    (pk, pinning)
                } else {
                    let input =
                        InputMerkleAggregation::new([EnhancedSnark::new(snarks[0].clone(), None)]);
                    let mut circuit =
                        input.build(CircuitBuilderStage::Keygen, pinning.params, &params).unwrap();
                    circuit.calculate_params(Some(9));
                    let pk = gen_pk(&params, &circuit, Some(&pk_path));
                    let pinning =
                        AggregationCircuitPinning::new(circuit.params(), circuit.break_points());
                    write_json(pinning_path, &pinning);
                    (pk, pinning)
                };
            let prev_snarks = std::mem::take(&mut snarks);

            if r < round {
                let mut start = start_num;
                for snark in prev_snarks {
                    let stop = std::cmp::min(start + (1 << depth), stop_num);
                    let input = InputMerkleAggregation::new([EnhancedSnark::new(snark, None)]);
                    let circuit = input
                        .build(CircuitBuilderStage::Prover, pinning.params, &params)
                        .unwrap()
                        .use_break_points(pinning.break_points.clone());
                    let snark_path = format!("data/tests/{}_{}_{}.snark", &name, start, stop);
                    let snark = gen_snark_shplonk(&params, &pk, circuit, Some(snark_path));
                    snarks.push(snark);
                    start = stop;
                }
            } else {
                // FINAL ROUND, do evm verification, requires solc installed
                let num_instance = NUM_FE_ACCUMULATOR + 5 + 2 * (depth + 1);
                let sol_path = PathBuf::from(format!("data/tests/{}.sol", &name));
                let deploy_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
                    &params,
                    pk.get_vk(),
                    vec![num_instance],
                    Some(&sol_path),
                );
                for snark in prev_snarks {
                    let input = InputMerkleAggregation::new([EnhancedSnark::new(snark, None)]);
                    let circuit = input
                        .build(CircuitBuilderStage::Prover, pinning.params, &params)
                        .unwrap()
                        .use_break_points(pinning.break_points.clone());
                    let instances = circuit.instances();
                    let proof = gen_evm_proof_shplonk(&params, &pk, circuit, instances.clone());
                    evm_verify(deploy_code.clone(), instances.clone(), proof);
                    final_instances.push(instances);
                }
            }
        }
    }
    // all done!
    // check final instances
    // if not Finality::Evm, check instances from snarks
    if !snarks.is_empty() {
        for snark in &snarks {
            final_instances.push(snark.instances.clone());
        }
    }
    let mut start = start_num;
    for instances in final_instances {
        let stop = std::cmp::min(start + (1 << depth), stop_num);
        let blocks = &blocks[start - start_num..stop - start_num];
        let prev_hash = blocks[0].clone().unwrap().parent_hash;
        let block_hashes = blocks.iter().map(|b| b.clone().unwrap().hash.unwrap()).collect_vec();
        let end_hash = *block_hashes.last().unwrap();
        let mmr = get_merkle_mountain_range(&block_hashes, depth);
        let chain_instance = EthBlockHeaderChainInstance::new(
            prev_hash,
            end_hash,
            start as u32,
            stop as u32 - 1,
            mmr,
        )
        .to_instance();
        // instances has accumulator, remove it
        assert_eq!(&instances[0][NUM_FE_ACCUMULATOR..], &chain_instance);

        start = stop;
    }
}

#[test]
fn test_mainnet_header_chain_provider() {
    header_tree_aggregation(Chain::Mainnet, 0x765fb3, 0x765fb3 + 7, 3, 3, Finality::None);
}

#[test]
#[ignore = "requires a lot of memory"]
fn test_mainnet_header_chain_intermediate_aggregation() {
    header_tree_aggregation(Chain::Mainnet, 0x765fb3, 0x765fb3 + 11, 3, 4, Finality::None);
}

#[test]
#[ignore = "requires over 32G memory"]
fn test_mainnet_header_chain_root_aggregation() {
    header_tree_aggregation(Chain::Mainnet, 0x765fb3, 0x765fb3 + 11, 3, 5, Finality::Root);
}

#[test]
#[ignore = "requires over 32G memory and solc installed"]
fn test_mainnet_header_chain_aggregation_for_evm() {
    header_tree_aggregation(Chain::Mainnet, 0x765fb3, 0x765fb3 + 11, 3, 5, Finality::Evm(0));
}

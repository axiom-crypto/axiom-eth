#![allow(clippy::too_many_arguments)]
#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use axiom_eth::{
    block_header::{
        aggregation::{
            AggregationWithKeccakConfigParams, EthBlockHeaderChainAggregationCircuit,
            EthBlockHeaderChainFinalAggregationCircuit,
        },
        helpers::{gen_block_header_chain_snark, read_block_header_chain_snark},
        EthBlockHeaderChainInstance,
    },
    providers::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL},
    util::EthConfigParams,
    Network,
};
use clap::Parser;
use clap_num::maybe_hex;
use ethers_providers::{Http, Provider};
use halo2_base::utils::fs::gen_srs;
use rand::{Rng, SeedableRng};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{
        aggregation::load_verify_circuit_degree, gen_snark_shplonk, PoseidonTranscript,
        POSEIDON_SPEC,
    },
    NativeLoader, Snark,
};
use std::{
    cmp::min,
    env::{set_var, var},
    fs::{read_to_string, File},
    path::Path,
};

// starts from `initial_depth` and works up to `max_depth`, generating all snarks in between. tries to read snark from file first for continuity
// generates srs and pk once for each depth
pub fn batch_gen_block_header_chain_snarks(
    provider: &Provider<Http>,
    network: Network,
    start_block_number: u32,
    end_block_number: u32,
    max_depth: usize,
    initial_depth: usize,
    create_merkle_roots: bool,
    transcript: &mut PoseidonTranscript<NativeLoader, Vec<u8>>,
    rng: &mut (impl Rng + Send),
) {
    let capacity = ((end_block_number - start_block_number) >> initial_depth) as usize + 1;
    let mut snarks: Vec<Snark> = Vec::with_capacity(capacity);
    let mut instances: Vec<EthBlockHeaderChainInstance> = Vec::with_capacity(capacity);
    for depth in initial_depth..=max_depth {
        let name;
        let k = if depth == initial_depth {
            name = format!("data/headers/{network}_{depth}");
            set_var("BLOCK_HEADER_CONFIG", format!("configs/headers/{network}_{depth}.json"));
            EthConfigParams::get_header().degree
        } else if depth != max_depth || !create_merkle_roots {
            name = format!("data/headers/{network}_{depth}_{initial_depth}");
            set_var(
                "VERIFY_CONFIG",
                format!("configs/headers/{network}_{depth}_{initial_depth}.json"),
            );
            load_verify_circuit_degree()
        } else {
            name = format!("data/headers/{network}_{depth}_{initial_depth}");
            set_var(
                "FINAL_AGGREGATION_CONFIG",
                format!("configs/headers/{network}_{depth}_{initial_depth}_final.json"),
            );
            AggregationWithKeccakConfigParams::get().aggregation.degree
        };
        let is_final = depth == max_depth && create_merkle_roots && depth > initial_depth;

        let params = gen_srs(k);
        let mut pk = None;
        let mut prev_idx = 0;
        for start in (start_block_number..=end_block_number).step_by(1 << depth) {
            let end = min(start + (1 << depth) - 1, end_block_number);
            let (snark, instance) = if let Ok(snarki) =
                read_block_header_chain_snark(network, start, end, depth, initial_depth, is_final)
            {
                snarki
            } else if depth == initial_depth {
                let (snark, instance, cow_pk) = gen_block_header_chain_snark(
                    &params,
                    pk.as_ref(),
                    provider,
                    network,
                    start,
                    end,
                    depth,
                    transcript,
                    rng,
                );
                pk = Some(cow_pk.into_owned());
                (snark, instance)
            } else {
                let prev_snarks =
                    vec![snarks[2 * prev_idx].clone(), snarks[2 * prev_idx + 1].clone()];
                let prev_instances =
                    [instances[2 * prev_idx].clone(), instances[2 * prev_idx + 1].clone()];

                if !is_final {
                    let circuit = EthBlockHeaderChainAggregationCircuit::new(
                        &params,
                        prev_snarks,
                        prev_instances,
                        transcript,
                        rng,
                        end - start + 1,
                        depth,
                        initial_depth,
                    );
                    pk = pk.or_else(|| {
                        Some(gen_pk(&params, &circuit, Some(Path::new(&format!("{name}.pkey")))))
                    });
                    let name = format!("{name}_{start:6x}_{end:6x}");
                    let instance = circuit.chain_instance.clone();
                    bincode::serialize_into(File::create(format!("{name}.in")).unwrap(), &instance)
                        .unwrap();
                    let snark_path = format!("{name}.snark");
                    (
                        gen_snark_shplonk(
                            &params,
                            pk.as_ref().unwrap(),
                            circuit,
                            transcript,
                            rng,
                            Some(Path::new(&snark_path)),
                        ),
                        instance,
                    )
                } else {
                    let circuit = EthBlockHeaderChainFinalAggregationCircuit::new(
                        &params,
                        prev_snarks,
                        prev_instances,
                        transcript,
                        rng,
                        end - start + 1,
                        depth,
                        initial_depth,
                    );
                    pk = pk.or_else(|| {
                        Some(gen_pk(
                            &params,
                            &circuit,
                            Some(Path::new(&format!("{name}_final.pkey"))),
                        ))
                    });
                    let name = format!("{name}_{start:6x}_{end:6x}_final");
                    let instance = circuit.0.chain_instance.clone();
                    bincode::serialize_into(File::create(format!("{name}.in")).unwrap(), &instance)
                        .unwrap();
                    let snark_path = format!("{name}.snark");
                    (
                        gen_snark_shplonk(
                            &params,
                            pk.as_ref().unwrap(),
                            circuit,
                            transcript,
                            rng,
                            Some(Path::new(&snark_path)),
                        ),
                        instance,
                    )
                }
            };
            if depth == initial_depth {
                snarks.push(snark);
                instances.push(instance);
            } else {
                snarks[prev_idx] = snark;
                instances[prev_idx] = instance;
            }
            prev_idx += 1;
        }
        snarks.truncate(prev_idx);
        if depth != max_depth && (prev_idx & 1 == 1) {
            // need even number of snarks for aggregation, so insert dummy
            snarks.push(snarks[0].clone());
            instances.push(instances[0].clone());
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)] // Read from `Cargo.toml`
/// Generates multiple SNARKS for chains of block header hashes.
/// Optionally does final processing to get merkle mountain range and/or produce EVM verifier contract code and calldata.
struct Cli {
    #[arg(long, default_value_t = Network::Mainnet)]
    network: Network,
    #[arg(short, long = "start", value_parser=maybe_hex::<u32>)]
    start_block_number: u32,
    #[arg(short, long = "end", value_parser=maybe_hex::<u32>)]
    end_block_number: u32,
    #[arg(long = "max-depth")]
    max_depth: usize,
    #[arg(long = "initial-depth")]
    initial_depth: Option<usize>,
    #[arg(long = "final")]
    is_final: bool,
}

fn main() {
    let Cli { network, start_block_number, end_block_number, max_depth, initial_depth, is_final } =
        Cli::parse();
    let initial_depth = initial_depth.unwrap_or(max_depth);

    let infura_id = var("INFURA_ID").expect("Infura ID not found");
    let provider_url = match network {
        Network::Mainnet => MAINNET_PROVIDER_URL,
        Network::Goerli => GOERLI_PROVIDER_URL,
    };
    let provider = Provider::<Http>::try_from(format!("{provider_url}{infura_id}").as_str())
        .expect("could not instantiate HTTP Provider");

    let mut transcript =
        PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(vec![], POSEIDON_SPEC.clone());
    let mut rng = rand_chacha::ChaChaRng::from_entropy();

    #[cfg(feature = "display")]
    let start = start_timer!(|| format!(
        "Generating SNARKs for blocks {} to {}, max depth {}, initial depth {}, is_final: {}",
        start_block_number, end_block_number, max_depth, initial_depth, is_final
    ));

    batch_gen_block_header_chain_snarks(
        &provider,
        network,
        start_block_number,
        end_block_number,
        max_depth,
        initial_depth,
        is_final,
        &mut transcript,
        &mut rng,
    );

    #[cfg(feature = "display")]
    end_timer!(start);
}

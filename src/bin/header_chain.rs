#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use axiom_eth::{
    block_header::helpers::{
        autogen_final_block_header_chain_snark,
        evm::autogen_final_block_header_chain_snark_for_evm, gen_final_block_header_chain_snark,
        gen_multiple_block_header_chain_snarks,
    },
    providers::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL},
    Network,
};
use clap::{Parser, ValueEnum};
use clap_num::maybe_hex;
use ethers_providers::{Http, Provider};
use rand::SeedableRng;
use snark_verifier_sdk::{
    halo2::{PoseidonTranscript, POSEIDON_SPEC},
    NativeLoader,
};
use std::{fmt::Display, fs::read_to_string};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)] // Read from `Cargo.toml`
/// Generates multiple SNARKS for chains of block header hashes.
/// Optionally does final processing to get merkle mountain range and/or produce EVM verifier contract code and calldata.
struct Cli {
    #[arg(long, default_value_t = Network::Goerli)]
    network: Network,
    #[arg(short, long = "start", value_parser=maybe_hex::<u32>)]
    start_block_number: u32,
    #[arg(short, long = "end", value_parser=maybe_hex::<u32>)]
    end_block_number: u32,
    #[arg(long = "max-depth")]
    max_depth: usize,
    #[arg(long = "initial-depth")]
    initial_depth: Option<usize>,
    #[arg(long = "final", default_value_t = Finality::None)]
    finality: Finality,
    #[cfg_attr(feature = "evm", arg(long = "create-contract"))]
    create_contract: bool,
}

#[derive(Clone, Debug, ValueEnum)]
enum Finality {
    /// Produces as many snarks as needed to fit the entire block number range, without any final processing.
    None,
    /// The block number range must fit within the specified max depth.
    /// Produces a single final snark with the starting & ending block numbers, previous and last block hashes,
    /// and merkle mountain range as output.
    Merkle,
    /// The block number range must fit within the specified max depth. Produces the final verifier circuit to verifier all
    /// the previous snarks in EVM. Writes the calldata to disk.
    #[cfg(feature = "evm")]
    Evm,
}

impl Display for Finality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Finality::None => write!(f, "none"),
            Finality::Merkle => write!(f, "merkle"),
            #[cfg(feature = "evm")]
            Finality::Evm => write!(f, "evm"),
        }
    }
}

fn main() {
    let args = Cli::parse();
    let initial_depth = args.initial_depth.unwrap_or(args.max_depth);

    let infura_id = read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
    let provider_url = match args.network {
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
        "Generating SNARKs for blocks {} to {}, max depth {}, initial depth {}, finality {}",
        args.start_block_number,
        args.end_block_number,
        args.max_depth,
        initial_depth,
        args.finality
    ));
    match args.finality {
        Finality::None => {
            gen_multiple_block_header_chain_snarks(
                &provider,
                args.network,
                args.start_block_number,
                args.end_block_number,
                args.max_depth,
                initial_depth,
                &mut transcript,
                &mut rng,
            );
        }
        Finality::Merkle => {
            autogen_final_block_header_chain_snark(
                &provider,
                args.network,
                args.start_block_number,
                args.end_block_number,
                args.max_depth,
                initial_depth,
                &mut transcript,
                &mut rng,
            );
        }
        #[cfg(feature = "evm")]
        Finality::Evm => {
            autogen_final_block_header_chain_snark_for_evm(
                &provider,
                args.network,
                args.start_block_number,
                args.end_block_number,
                args.max_depth,
                initial_depth,
                args.create_contract,
                &mut transcript,
                &mut rng,
            );
        }
    }
    #[cfg(feature = "display")]
    end_timer!(start);
}

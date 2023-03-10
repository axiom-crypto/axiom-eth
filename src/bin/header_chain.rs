#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use axiom_eth::{
    block_header::helpers::{BlockHeaderScheduler, CircuitType, Finality, Task},
    util::scheduler::Scheduler,
    Network,
};
use clap::{Parser, ValueEnum};
use clap_num::maybe_hex;
use std::{cmp::min, fmt::Display, path::PathBuf};

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
    #[arg(long = "final", default_value_t = CliFinality::None)]
    finality: CliFinality,
    #[arg(long = "extra-rounds")]
    rounds: Option<usize>,
    #[arg(long = "calldata")]
    calldata: bool,
    #[cfg_attr(feature = "evm", arg(long = "create-contract"))]
    create_contract: bool,
    #[arg(long = "readonly")]
    readonly: bool,
}

#[derive(Clone, Debug, ValueEnum)]
enum CliFinality {
    /// Produces as many snarks as needed to fit the entire block number range, without any final processing.
    None,
    /// The block number range must fit within the specified max depth.
    /// Produces a single final snark with the starting & ending block numbers, previous and last block hashes,
    /// and merkle mountain range as output.
    Merkle,
    /// The block number range must fit within the specified max depth. Produces the final verifier circuit to verifier all
    /// the previous snarks in EVM. Writes the calldata to disk.
    Evm,
}

impl Display for CliFinality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliFinality::None => write!(f, "none"),
            CliFinality::Merkle => write!(f, "merkle"),
            CliFinality::Evm => write!(f, "evm"),
        }
    }
}

fn main() {
    let args = Cli::parse();
    let initial_depth = args.initial_depth.unwrap_or(args.max_depth);
    #[cfg(feature = "production")]
    let production = true;
    #[cfg(not(feature = "production"))]
    let production = false;

    let scheduler = BlockHeaderScheduler::new(
        args.network,
        production,
        args.readonly,
        PathBuf::from("configs/headers"),
        PathBuf::from("data/headers"),
    );

    #[cfg(feature = "display")]
    let start = start_timer!(|| format!(
        "Generating SNARKs for blocks {} to {}, max depth {}, initial depth {}, finality {}",
        args.start_block_number,
        args.end_block_number,
        args.max_depth,
        initial_depth,
        args.finality
    ));

    let finality = match args.finality {
        CliFinality::None => Finality::None,
        CliFinality::Merkle => Finality::Merkle,
        CliFinality::Evm => Finality::Evm(args.rounds.unwrap_or(0)),
    };
    let circuit_type = CircuitType::new(args.max_depth, initial_depth, finality, args.network);
    for start in (args.start_block_number..=args.end_block_number).step_by(1 << args.max_depth) {
        let end = min(start + (1 << args.max_depth) - 1, args.end_block_number);
        let task = Task::new(start, end, circuit_type);
        if args.calldata {
            #[cfg(feature = "evm")]
            scheduler.get_calldata(task, args.create_contract);
        } else {
            scheduler.get_snark(task);
        }
    }

    #[cfg(feature = "display")]
    end_timer!(start);
}

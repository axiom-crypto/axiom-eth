// Copied from uniswap-v3-oracles/circuits/src/bin/v3_twap_proof.rs
use axiom_eth::{
    storage::helpers::{StorageScheduler, StorageTask},
    util::scheduler::{evm_wrapper::Wrapper::ForEvm, Scheduler},
    Network,
};
use clap::Parser;
use std::{fs::File, path::PathBuf};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)] // Read from `Cargo.toml`
/// Generates ZK SNARK that reads historical oracle observations from a Uniswap V3 Pool smart contract
/// for TWAP computations.
/// The output is the proof calldata to send to the EVM SNARK verifier or Axiom's specialized TWAP Oracle contract.
/// Optionally produces the EVM verifier contract Yul code.
struct Cli {
    #[arg(long, default_value_t = Network::Mainnet)]
    network: Network,
    #[arg(long = "path")]
    json_path: String,
    #[arg(long = "create-contract")]
    create_contract: bool,
    #[arg(long = "readonly")]
    readonly: bool,
    #[arg(long = "srs-readonly")]
    srs_readonly: bool,
    #[arg(short, long = "config-path")]
    config_path: Option<PathBuf>,
    #[arg(short, long = "data-path")]
    data_path: Option<PathBuf>,
}

fn main() {
    let args = Cli::parse();
    #[cfg(feature = "production")]
    let srs_readonly = true;
    #[cfg(not(feature = "production"))]
    let srs_readonly = args.srs_readonly;

    let scheduler = StorageScheduler::new(
        args.network,
        srs_readonly,
        args.readonly,
        args.config_path.unwrap_or_else(|| PathBuf::from("configs/storage")),
        args.data_path.unwrap_or_else(|| PathBuf::from("data/storage")),
    );
    let task: StorageTask = serde_json::from_reader(File::open(args.json_path).unwrap()).unwrap();

    scheduler.get_calldata(ForEvm(task), args.create_contract);
}

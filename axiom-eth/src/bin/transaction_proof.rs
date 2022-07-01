use axiom_eth::{
    transaction::helpers::{TransactionScheduler, TransactionTask},
    util::scheduler::{evm_wrapper::Wrapper::ForEvm, Scheduler},
    Network,
};
use clap::Parser;
use std::{fs::File, path::PathBuf};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)] // Read from `Cargo.toml`
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

    let scheduler = TransactionScheduler::new(
        args.network,
        srs_readonly,
        args.readonly,
        args.config_path.unwrap_or_else(|| PathBuf::from("configs/transaction")),
        args.data_path.unwrap_or_else(|| PathBuf::from("data")),
    );
    let mut task: TransactionTask =
        serde_json::from_reader(File::open(args.json_path).unwrap()).unwrap();
    task.resize(8);
    scheduler.get_calldata(ForEvm(task), args.create_contract);
}

use axiom_eth::{
    receipt::task::{OnlyReceiptsQuery, OnlyReceiptsScheduler},
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

const ONLY_RECEIPTS_MAX_SIZE: usize = 8;

fn main() {
    let args = Cli::parse();
    #[cfg(feature = "production")]
    let srs_readonly = true;
    #[cfg(not(feature = "production"))]
    let srs_readonly = args.srs_readonly;

    let scheduler = OnlyReceiptsScheduler::new(
        args.network,
        srs_readonly,
        args.readonly,
        args.config_path.unwrap_or_else(|| PathBuf::from("configs/receipts")),
        args.data_path.unwrap_or_else(|| PathBuf::from("data/receipts")),
    );
    let mut task: OnlyReceiptsQuery =
        serde_json::from_reader(File::open(args.json_path).unwrap()).unwrap();
    task.network = Some(args.network);
    if task.queries.is_empty() {
        panic!("You have not provided any queries!");
    }
    if task.queries.len() > ONLY_RECEIPTS_MAX_SIZE {
        panic!("Too many queries: max size is {ONLY_RECEIPTS_MAX_SIZE}");
    }
    assert_eq!(task.queries.len(), task.mmr_proofs.len());
    // resize to max
    while task.queries.len() != ONLY_RECEIPTS_MAX_SIZE {
        task.queries.push(task.queries[0].clone());
        task.mmr_proofs.push(task.mmr_proofs[0].clone());
    }

    scheduler.get_calldata(ForEvm(task), args.create_contract);
}

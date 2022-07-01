use axiom_eth::util::scheduler::{evm_wrapper::Wrapper::ForEvm, Scheduler};
use axiom_eth::{
    batch_query::response::transaction_receipt::MultiTransactionReceiptCircuit,
    receipt::{ReceiptRequest, RECEIPT_MAX_DATA_BYTES, RECEIPT_MAX_LOG_NUM},
    transaction::{TransactionRequest, TRANSACTION_MAX_DATA_BYTES},
    util::scheduler::{
        evm_wrapper::{EvmWrapper, SimpleTask},
        CircuitType, Task,
    },
    Network,
};
use clap::Parser;
use ethers_core::{types::H256, utils::keccak256};
use ethers_providers::{Http, Provider, RetryClient};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxReceiptsQuery {
    pub tx_queries: Vec<TransactionRequest>,
    pub receipt_queries: Vec<ReceiptRequest>,
    pub mmr: Vec<H256>,
    pub tx_mmr_proofs: Vec<Vec<H256>>,
    pub receipt_mmr_proofs: Vec<Vec<H256>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<Network>,
}

impl TxReceiptsQuery {
    pub fn network(&self) -> Network {
        self.network.unwrap_or(Network::Mainnet)
    }

    pub fn digest(&self) -> H256 {
        H256(keccak256(bincode::serialize(&self).unwrap()))
    }
}

impl Task for TxReceiptsQuery {
    type CircuitType = (Network, usize);

    fn circuit_type(&self) -> Self::CircuitType {
        (self.network(), self.tx_queries.len() + self.receipt_queries.len())
    }
    fn name(&self) -> String {
        format!("{}_{:?}", self.circuit_type().name(), self.digest())
    }
    fn dependencies(&self) -> Vec<Self> {
        vec![]
    }
}

pub type TransactionReceiptScheduler = EvmWrapper<TxReceiptsQuery>;

impl SimpleTask for TxReceiptsQuery {
    type PreCircuit = MultiTransactionReceiptCircuit;

    fn get_circuit(
        &self,
        provider: Arc<Provider<RetryClient<Http>>>,
        network: Network,
    ) -> Self::PreCircuit {
        MultiTransactionReceiptCircuit::from_provider(
            &provider,
            self.tx_queries.clone(),
            self.receipt_queries.clone(),
            network,
            self.mmr.clone(),
            self.tx_mmr_proofs.clone(),
            self.receipt_mmr_proofs.clone(),
            TRANSACTION_MAX_DATA_BYTES,
            0,
            [true, false, true],
            RECEIPT_MAX_DATA_BYTES,
            RECEIPT_MAX_LOG_NUM,
            (0, 4),
        )
    }
}

fn main() {
    let args = Cli::parse();
    #[cfg(feature = "production")]
    let srs_readonly = true;
    #[cfg(not(feature = "production"))]
    let srs_readonly = args.srs_readonly;

    let scheduler = TransactionReceiptScheduler::new(
        args.network,
        srs_readonly,
        args.readonly,
        args.config_path.unwrap_or_else(|| PathBuf::from("configs/tx_receipts")),
        args.data_path.unwrap_or_else(|| PathBuf::from("data/tx_receipts")),
    );
    let mut task: TxReceiptsQuery =
        serde_json::from_reader(File::open(args.json_path).unwrap()).unwrap();
    task.network = Some(args.network);

    if task.tx_queries.is_empty() && task.receipt_queries.is_empty() {
        panic!("No queries");
    }
    if task.tx_queries.is_empty() {
        task.tx_queries
            .push(TransactionRequest { tx_hash: task.receipt_queries[0].tx_hash, field_idx: 0 });
        task.tx_mmr_proofs.push(task.receipt_mmr_proofs[0].clone());
    }
    if task.receipt_queries.is_empty() {
        task.receipt_queries.push(ReceiptRequest {
            tx_hash: task.tx_queries[0].tx_hash,
            field_idx: 0,
            log_idx: None,
        });
        task.receipt_mmr_proofs.push(task.tx_mmr_proofs[0].clone());
    }
    assert!(task.tx_queries.len() <= 4);
    assert!(task.receipt_queries.len() <= 4);
    assert_eq!(task.tx_queries.len(), task.tx_mmr_proofs.len());
    assert_eq!(task.receipt_queries.len(), task.receipt_mmr_proofs.len());
    while task.tx_queries.len() < 4 {
        task.tx_queries.push(task.tx_queries[0].clone());
        task.tx_mmr_proofs.push(task.tx_mmr_proofs[0].clone())
    }
    while task.receipt_queries.len() < 4 {
        task.receipt_queries.push(task.receipt_queries[0].clone());
        task.receipt_mmr_proofs.push(task.receipt_mmr_proofs[0].clone())
    }

    scheduler.get_calldata(ForEvm(task), args.create_contract);
}

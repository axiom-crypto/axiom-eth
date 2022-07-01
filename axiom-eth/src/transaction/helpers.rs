use crate::{
    batch_query::response::transaction::MultiTransactionCircuit,
    util::{
        scheduler::{
            evm_wrapper::{EvmWrapper, SimpleTask},
            CircuitType, Task,
        },
        EthConfigPinning, Halo2ConfigPinning,
    },
    Network,
};
use ethers_core::{types::H256, utils::keccak256};
use ethers_providers::{Http, Provider, RetryClient};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub use super::EthBlockTransactionCircuit;
use super::TRANSACTION_MAX_DATA_BYTES;

pub type TransactionScheduler = EvmWrapper<TransactionTask>;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionTask {
    pub block_numbers: Vec<u32>,
    pub queries: Vec<(usize, usize)>,
    pub mmr: Vec<H256>,
    pub mmr_list_len: usize,
    pub mmr_proofs: Vec<Vec<H256>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<Network>,
}

impl TransactionTask {
    pub fn new(
        block_numbers: Vec<u32>,
        queries: Vec<(usize, usize)>,
        network: Network,
        mmr: Vec<H256>,
        mmr_list_len: usize,
        mmr_proofs: Vec<Vec<H256>>,
    ) -> Self {
        Self { block_numbers, queries, network: Some(network), mmr, mmr_list_len, mmr_proofs }
    }

    pub fn resize(&mut self, new_len: usize) {
        assert!(!self.queries.is_empty());
        self.block_numbers.resize(new_len, self.block_numbers[0]);
        self.queries.resize(new_len, self.queries[0]);
        self.mmr_proofs.resize(new_len, self.mmr_proofs[0].clone());
    }

    pub fn network(&self) -> Network {
        self.network.unwrap_or(Network::Mainnet)
    }

    pub fn digest(&self) -> H256 {
        H256(keccak256(bincode::serialize(&self).unwrap()))
    }
}

impl CircuitType for (Network, usize) {
    fn name(&self) -> String {
        format!("{}_{}", self.0, self.1)
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<std::path::Path>) -> u32 {
        let pinning_path = pinning_path.as_ref();
        let pinning = EthConfigPinning::from_path(pinning_path);
        pinning.degree()
    }
}
impl Task for TransactionTask {
    type CircuitType = (Network, usize); // num slots

    fn circuit_type(&self) -> Self::CircuitType {
        (self.network(), self.queries.len())
    }
    fn name(&self) -> String {
        format!("{}_{:?}", self.circuit_type().name(), self.digest())
    }
    fn dependencies(&self) -> Vec<Self> {
        vec![]
    }
}

impl SimpleTask for TransactionTask {
    type PreCircuit = MultiTransactionCircuit;

    fn get_circuit(
        &self,
        provider: Arc<Provider<RetryClient<Http>>>,
        network: Network,
    ) -> Self::PreCircuit {
        MultiTransactionCircuit::from_provider(
            &provider,
            self.queries.clone(),
            self.block_numbers.clone(),
            network,
            self.mmr.clone(),
            self.mmr_proofs.clone(),
            TRANSACTION_MAX_DATA_BYTES,
            0,
            [true, false, true],
        )
    }
}

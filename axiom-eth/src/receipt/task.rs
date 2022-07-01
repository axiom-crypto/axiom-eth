use crate::{
    batch_query::response::receipts::MultiReceiptCircuit,
    util::scheduler::{
        evm_wrapper::{EvmWrapper, SimpleTask},
        CircuitType, Task,
    },
    Network,
};
use ethers_core::{types::H256, utils::keccak256};
use ethers_providers::{Http, Provider, RetryClient};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::{ReceiptRequest, RECEIPT_MAX_DATA_BYTES, RECEIPT_MAX_LOG_NUM};

pub type OnlyReceiptsScheduler = EvmWrapper<OnlyReceiptsQuery>;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnlyReceiptsQuery {
    pub queries: Vec<ReceiptRequest>,
    pub mmr: Vec<H256>,
    pub mmr_proofs: Vec<Vec<H256>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
}

impl OnlyReceiptsQuery {
    pub fn new(
        queries: Vec<ReceiptRequest>,
        mmr: Vec<H256>,
        mmr_proofs: Vec<Vec<H256>>,
        network: Network,
    ) -> Self {
        Self { network: Some(network), mmr, mmr_proofs, queries }
    }

    pub fn network(&self) -> Network {
        self.network.unwrap_or(Network::Mainnet)
    }

    pub fn digest(&self) -> H256 {
        H256(keccak256(bincode::serialize(&self).unwrap()))
    }
}

impl Task for OnlyReceiptsQuery {
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

impl SimpleTask for OnlyReceiptsQuery {
    type PreCircuit = MultiReceiptCircuit;

    fn get_circuit(
        &self,
        provider: Arc<Provider<RetryClient<Http>>>,
        network: Network,
    ) -> Self::PreCircuit {
        MultiReceiptCircuit::from_provider(
            &provider,
            self.queries.clone(),
            network,
            self.mmr.clone(),
            self.mmr_proofs.clone(),
            RECEIPT_MAX_DATA_BYTES,
            RECEIPT_MAX_LOG_NUM,
            (0, 4),
        )
    }
}

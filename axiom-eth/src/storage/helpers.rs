use crate::{
    util::{
        scheduler::{
            evm_wrapper::{EvmWrapper, SimpleTask},
            CircuitType, Task,
        },
        EthConfigPinning, Halo2ConfigPinning,
    },
    Network,
};
use ethers_core::{
    types::{Address, H256},
    utils::keccak256,
};
use ethers_providers::{Http, Provider, RetryClient};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub use super::EthBlockStorageCircuit;

pub type StorageScheduler = EvmWrapper<StorageTask>;

pub const ACCOUNT_PROOF_MAX_DEPTH: usize = 10;
pub const STORAGE_PROOF_MAX_DEPTH: usize = 10;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct StorageTask {
    pub block_number: u32,
    pub address: Address,
    pub slots: Vec<H256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<Network>,
}

impl StorageTask {
    pub fn new(block_number: u32, address: Address, slots: Vec<H256>, network: Network) -> Self {
        Self { block_number, address, slots, network: Some(network) }
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
impl Task for StorageTask {
    type CircuitType = (Network, usize); // num slots

    fn circuit_type(&self) -> Self::CircuitType {
        (self.network(), self.slots.len())
    }
    fn name(&self) -> String {
        format!("{}_{:?}", self.circuit_type().name(), self.digest())
    }
    fn dependencies(&self) -> Vec<Self> {
        vec![]
    }
}

impl SimpleTask for StorageTask {
    type PreCircuit = EthBlockStorageCircuit;

    fn get_circuit(
        &self,
        provider: Arc<Provider<RetryClient<Http>>>,
        network: Network,
    ) -> Self::PreCircuit {
        EthBlockStorageCircuit::from_provider(
            &provider,
            self.block_number,
            self.address,
            self.slots.clone(),
            ACCOUNT_PROOF_MAX_DEPTH,
            STORAGE_PROOF_MAX_DEPTH,
            network,
        )
    }
}

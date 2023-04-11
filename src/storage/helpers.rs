use crate::{
    rlp::builder::RlcThreadBuilder,
    util::{
        circuit::{PinnableCircuit, PreCircuit},
        scheduler::{
            evm_wrapper::{EvmWrapper, SimpleTask},
            Task,
        },
        EthConfigPinning,
    },
    Network,
};
use ethers_core::{
    types::{Address, H256},
    utils::keccak256,
};
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::builder::CircuitBuilderStage,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr},
        poly::kzg::commitment::ParamsKZG,
    },
};
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

impl Task for StorageTask {
    type CircuitType = (Network, usize); // num slots

    fn circuit_type(&self) -> Self::CircuitType {
        (self.network(), self.slots.len())
    }
    fn type_name((network, num_slots): Self::CircuitType) -> String {
        format!("{network}_{num_slots}")
    }
    fn name(&self) -> String {
        format!("{}_{:?}", Self::type_name(self.circuit_type()), self.digest())
    }
    fn dependencies(&self) -> Vec<Self> {
        vec![]
    }
}

impl SimpleTask for StorageTask {
    type PreCircuit = EthBlockStorageCircuit;

    fn get_circuit(&self, provider: Arc<Provider<Http>>, network: Network) -> Self::PreCircuit {
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

impl PreCircuit for EthBlockStorageCircuit {
    type Pinning = EthConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        _: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        let builder = match stage {
            CircuitBuilderStage::Prover => RlcThreadBuilder::new(true),
            _ => RlcThreadBuilder::new(false),
        };
        let break_points = pinning.map(|p| p.break_points);
        self.create_circuit::<Fr>(builder, break_points)
    }
}

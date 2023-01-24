use std::{
    collections::HashMap,
    env::{set_var, var},
    path::Path,
    vec,
};
use crate::{
    providers::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL},
    util::EthConfigParams,
    Field, Network,
};
use ethers_core::types::{Address, H256};
use ethers_providers::{Http, Provider};
use halo2_base::{
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::ProvingKey,
        poly::kzg::commitment::ParamsKZG,
    },
    utils::{fs::{gen_srs, read_params}, PrimeField},
};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use snark_verifier::loader::evm::encode_calldata;
use snark_verifier_sdk::{halo2::{aggregation::{PublicAggregationCircuit, load_verify_circuit_degree}, gen_snark_shplonk}, evm::gen_evm_proof_shplonk, CircuitExt, gen_pk};

use super::EthBlockStorageCircuit;

#[derive(Clone, Debug)]
pub struct Task {
    pub block_number: u32,
    pub address: Address,
    pub slots: Vec<H256>,
}

pub struct Sequencer {
    pub num_slot_to_pkey: HashMap<u32, ProvingKey<G1Affine>>,
    pub num_slot_to_k: HashMap<u32, u32>,
    pub num_slot_to_evm_k: HashMap<u32, u32>,
    pub params: HashMap<u32, ParamsKZG<Bn256>>,
    pub rng: ChaCha20Rng,
    pub provider: Provider<Http>,
    pub network: Network,
}

impl Sequencer {
    pub fn new(network: Network) -> Self {
        let infura_id = var("INFURA_ID").expect("Infura ID not found");
        let provider_url = match network {
            Network::Mainnet => MAINNET_PROVIDER_URL,
            Network::Goerli => GOERLI_PROVIDER_URL,
        };
        let provider = Provider::<Http>::try_from(format!("{provider_url}{infura_id}").as_str())
            .expect("could not instantiate HTTP Provider");

        Sequencer {
            num_slot_to_pkey: HashMap::new(),
            num_slot_to_k: HashMap::new(),
            num_slot_to_evm_k: HashMap::new(),
            params: HashMap::new(),
            provider,
            network,
            rng: ChaCha20Rng::from_entropy(),
        }
    }

    pub fn get_params(&mut self, num_slots: u32, params_dir: &str) {
        let network = self.network;
        let fname_prefix = format!("configs/storage/{network}_{num_slots}");
        let k = {
            set_var("STORAGE_CONFIG", format!("{fname_prefix}.json"));
            EthConfigParams::get_storage().degree
        };
        let evm_k = {
            set_var("VERIFY_CONFIG", format!("{fname_prefix}_evm.json"));
            load_verify_circuit_degree()
        };
        self.num_slot_to_k.insert(num_slots, k);
        self.num_slot_to_evm_k.insert(num_slots, evm_k);

        set_var("PARAMS_DIR", params_dir);
        self.params.entry(k).or_insert_with(||read_params(k));
        self.params.entry(evm_k).or_insert_with(||read_params(evm_k));
    }

    pub fn get_calldata(&mut self, task: Task, generate_smart_contract: bool) -> Vec<u8> {
        let mut rng = self.rng.clone();
        let network = self.network;
        let circuit = EthBlockStorageCircuit::from_provider(
            &self.provider,
            task.block_number,
            task.address,
            task.slots.clone(),
            8,
            8,
            network,
        );

        let k = self.num_slot_to_k[&(task.slots.len() as u32)];
        let params = &self.params[&k];
        let pk = gen_pk(params, &circuit, None);
        let snark = gen_snark_shplonk(params, &pk, circuit, &mut rng, None::<&str>);

        let evm_k = self.num_slot_to_evm_k[&(task.slots.len() as u32)];
        let evm_params = &self.params[&evm_k];
        let evm_circuit = PublicAggregationCircuit::new(
            evm_params,
            vec![snark],
            false,
            &mut rng,
        );
        let evm_pk = &gen_pk(evm_params, &evm_circuit, None);
        let instances = evm_circuit.instances();
        let evm_snark = gen_evm_proof_shplonk(evm_params, evm_pk, evm_circuit, instances.clone(), &mut rng);

        let calldata = encode_calldata(&instances, &evm_snark);
        calldata
    }
}
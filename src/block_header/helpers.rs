use super::{
    aggregation::{
        AggregationWithKeccakConfigParams, EthBlockHeaderChainAggregationCircuit,
        EthBlockHeaderChainFinalAggregationCircuit,
    },
    EthBlockHeaderChainCircuit,
};
use crate::{
    providers::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL},
    util::EthConfigParams,
    Field, Network,
};
use core::cmp::min;
use ethers_providers::{Http, Provider};
use halo2_base::{
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::ProvingKey,
        poly::kzg::commitment::ParamsKZG,
    },
    utils::{fs::gen_srs, PrimeField},
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{
        aggregation::{load_verify_circuit_degree, PublicAggregationCircuit},
        gen_snark_shplonk, read_snark,
    },
    CircuitExt, Snark, LIMBS,
};
use std::{
    collections::HashMap,
    env::{set_var, var},
    path::Path,
    vec,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Finality {
    /// Produces as many snarks as needed to fit the entire block number range, without any final processing.
    None,
    /// The block number range must fit within the specified max depth.
    /// Produces a single final snark with the starting & ending block numbers, previous and last block hashes,
    /// and merkle mountain range as output.
    Merkle,
    /// The block number range must fit within the specified max depth. `Evm(round)` performs `round + 1`
    /// rounds of SNARK verification on the final `Merkle` circuit
    Evm(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CircuitType {
    pub depth: usize,
    pub initial_depth: usize,
    pub finality: Finality,
}

impl CircuitType {
    pub fn new(depth: usize, initial_depth: usize, finality: Finality) -> Self {
        Self { depth, initial_depth, finality }
    }

    pub fn prev(&self) -> Self {
        assert!(self.depth != self.initial_depth, "Trying to call prev on initial circuit");
        match self.finality {
            Finality::None | Finality::Merkle => {
                Self::new(self.depth - 1, self.initial_depth, Finality::None)
            }
            Finality::Evm(round) => {
                if round == 0 {
                    Self::new(self.depth, self.initial_depth, Finality::Merkle)
                } else {
                    Self::new(self.depth, self.initial_depth, Finality::Evm(round - 1))
                }
            }
        }
    }

    pub fn fname_prefix(&self, network: Network) -> String {
        if self.depth == self.initial_depth {
            format!("data/headers/{network}_{}", self.depth)
        } else {
            format!("data/headers/{network}_{}_{}", self.depth, self.initial_depth)
        }
    }

    pub fn fname_suffix(&self) -> String {
        match self.finality {
            Finality::None => "".to_string(),
            Finality::Merkle => "_final".to_string(),
            Finality::Evm(round) => format!("_for_evm_{round}"),
        }
    }

    pub fn pkey_name(&self, network: Network) -> String {
        format!("{}{}.pkey", self.fname_prefix(network), self.fname_suffix())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Task {
    pub start: u32,
    pub end: u32,
    pub circuit_type: CircuitType,
}

impl Task {
    pub fn new(start: u32, end: u32, circuit_type: CircuitType) -> Self {
        Self { start, end, circuit_type }
    }

    pub fn snark_name(&self, network: Network) -> String {
        format!(
            "{}_{:06x}_{:06x}{}.snark",
            self.circuit_type.fname_prefix(network),
            self.start,
            self.end,
            self.circuit_type.fname_suffix()
        )
    }

    pub fn read_snark(&self, network: Network) -> Result<Snark, bincode::Error> {
        assert!(self.end - self.start < 1 << self.circuit_type.depth);
        read_snark(self.snark_name(network))
    }
}

pub enum AnyCircuit {
    Initial(EthBlockHeaderChainCircuit<Fr>),
    Intermediate(EthBlockHeaderChainAggregationCircuit),
    Final(EthBlockHeaderChainFinalAggregationCircuit),
    ForEvm(PublicAggregationCircuit),
}

pub struct Sequencer {
    pub pkeys: HashMap<CircuitType, ProvingKey<G1Affine>>,
    pub params_k: HashMap<CircuitType, u32>,
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
            pkeys: HashMap::new(),
            params_k: HashMap::new(),
            params: HashMap::new(),
            provider,
            network,
            rng: ChaCha20Rng::from_entropy(),
        }
    }

    pub fn get_params(&mut self, circuit_type: CircuitType) -> u32 {
        let network = self.network;
        let CircuitType { depth, initial_depth, finality } = circuit_type;
        let fname_prefix = if depth == initial_depth {
            format!("configs/headers/{network}_{depth}")
        } else {
            format!("configs/headers/{network}_{depth}_{initial_depth}")
        };
        let k = if depth == initial_depth {
            set_var("BLOCK_HEADER_CONFIG", format!("{fname_prefix}.json"));
            EthConfigParams::get_header().degree
        } else {
            match finality {
                Finality::None => {
                    set_var("VERIFY_CONFIG", format!("{fname_prefix}.json"));
                    load_verify_circuit_degree()
                }
                Finality::Merkle => {
                    set_var("FINAL_AGGREGATION_CONFIG", format!("{fname_prefix}_final.json"));
                    AggregationWithKeccakConfigParams::get().aggregation.degree
                }
                Finality::Evm(round) => {
                    set_var("VERIFY_CONFIG", format!("{fname_prefix}_for_evm_{round}.json"));
                    load_verify_circuit_degree()
                }
            }
        };
        self.params.entry(k).or_insert_with(|| gen_srs(k));
        self.params_k.insert(circuit_type, k);
        k
    }

    // recursively generates necessary snarks to create circuit
    pub fn get_circuit(&mut self, task: Task) -> AnyCircuit {
        let Task { start, end, circuit_type } = task;
        let CircuitType { depth, initial_depth, finality } = circuit_type;
        assert!(end - start < 1 << depth);
        if depth == initial_depth {
            // set environmental vars
            self.get_params(circuit_type);
            let circuit = EthBlockHeaderChainCircuit::from_provider(
                &self.provider,
                self.network,
                start,
                end - start + 1,
                depth,
            );
            AnyCircuit::Initial(circuit)
        } else {
            let prev_type = circuit_type.prev();
            let mut snarks: Vec<Snark>;
            let prev_depth = prev_type.depth;
            snarks = (start..=end)
                .step_by(1 << prev_depth)
                .map(|i| {
                    self.get_snark(Task::new(i, min(end, i + (1 << prev_depth) - 1), prev_type))
                })
                .collect();
            if (finality == Finality::None || finality == Finality::Merkle) && snarks.len() != 2 {
                snarks.push(snarks[0].clone());
            }
            let k = self.get_params(circuit_type);
            let params = self.params.get(&k).unwrap();
            let mut rng = self.rng.clone();
            match finality {
                Finality::None => {
                    let circuit = EthBlockHeaderChainAggregationCircuit::new(
                        params,
                        snarks,
                        &mut rng,
                        end - start + 1,
                        depth,
                        initial_depth,
                    );
                    AnyCircuit::Intermediate(circuit)
                }
                Finality::Merkle => {
                    let circuit = EthBlockHeaderChainFinalAggregationCircuit::new(
                        params,
                        snarks,
                        &mut rng,
                        end - start + 1,
                        depth,
                        initial_depth,
                    );
                    AnyCircuit::Final(circuit)
                }
                Finality::Evm(_) => {
                    let circuit = PublicAggregationCircuit::new(params, snarks, true, &mut rng);
                    AnyCircuit::ForEvm(circuit)
                }
            }
        }
    }

    // recursively generates necessary circuits and snarks to create snark
    pub fn get_snark(&mut self, task: Task) -> Snark {
        let network = self.network;
        if let Ok(snark) = task.read_snark(network) {
            return snark;
        }
        let circuit = self.get_circuit(task);
        let circuit_type = task.circuit_type;
        let params = &self.params[&self.params_k[&circuit_type]];
        let pk_name = circuit_type.pkey_name(network);
        let pk_path = Some(Path::new(&pk_name));
        let pk = self.pkeys.entry(circuit_type).or_insert_with(|| {
            // as you can see we do the same thing for each circuit, but because `Circuit` is
            // not an object-safe trait we can't put it in a `Box`
            match &circuit {
                AnyCircuit::Initial(circuit) => gen_pk(params, circuit, pk_path),
                AnyCircuit::Intermediate(circuit) => gen_pk(params, circuit, pk_path),
                AnyCircuit::Final(circuit) => gen_pk(params, circuit, pk_path),
                AnyCircuit::ForEvm(circuit) => gen_pk(params, circuit, pk_path),
            }
        });
        let snark_path = Some(task.snark_name(network));
        let mut rng = self.rng.clone();
        match circuit {
            AnyCircuit::Initial(circuit) => {
                gen_snark_shplonk(params, pk, circuit, &mut rng, snark_path)
            }
            AnyCircuit::Intermediate(circuit) => {
                gen_snark_shplonk(params, pk, circuit, &mut rng, snark_path)
            }
            AnyCircuit::Final(circuit) => {
                gen_snark_shplonk(params, pk, circuit, &mut rng, snark_path)
            }
            AnyCircuit::ForEvm(circuit) => {
                gen_snark_shplonk(params, pk, circuit, &mut rng, snark_path)
            }
        }
    }

    #[cfg(feature = "evm")]
    pub fn get_calldata(&mut self, task: Task, generate_smart_contract: bool) -> Vec<u8> {
        let network = self.network;
        let circuit_type = task.circuit_type;
        assert!(matches!(circuit_type.finality, Finality::Evm(_)));
        let fname = format!(
            "data/headers/{}_{}_{}_{:06x}_{:06x}.calldata",
            network, circuit_type.depth, circuit_type.initial_depth, task.start, task.end
        );
        if let Ok(calldata) = std::fs::read(&fname) {
            return calldata;
        }

        let circuit = self.get_circuit(task);
        match circuit {
            AnyCircuit::ForEvm(circuit) => {
                self.write_calldata_generic(circuit, circuit_type, &fname, generate_smart_contract)
            }
            _ => unreachable!(),
        }
    }

    #[cfg(feature = "evm")]
    fn write_calldata_generic<ConcreteCircuit: CircuitExt<Fr>>(
        &mut self,
        circuit: ConcreteCircuit,
        circuit_type: CircuitType,
        path: impl AsRef<Path>,
        generate_smart_contract: bool,
    ) -> Vec<u8> {
        #[allow(unused_imports)]
        use ethers_core::utils::hex;
        use snark_verifier::loader::evm::encode_calldata;
        use snark_verifier_sdk::evm::{
            evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk,
        };
        use std::fs;

        let params = &self.params[&self.params_k[&circuit_type]];
        let pk_name = circuit_type.pkey_name(self.network);
        let pk_path = Some(Path::new(&pk_name));
        let pk =
            self.pkeys.entry(circuit_type).or_insert_with(|| gen_pk(params, &circuit, pk_path));
        let instances = circuit.instances();
        let mut rng = self.rng.clone();
        let proof = gen_evm_proof_shplonk(params, pk, circuit, instances.clone(), &mut rng);
        let calldata = encode_calldata(&instances, &proof);
        fs::write(path, hex::encode(&calldata)).expect("write calldata should not fail");

        if generate_smart_contract {
            let num_instances = instances[0].len();
            let deployment_code = gen_evm_verifier_shplonk::<ConcreteCircuit>(
                params,
                pk.get_vk(),
                vec![num_instances],
                Some(Path::new(&format!(
                    "data/headers/{}_{}_{}.yul",
                    self.network, circuit_type.depth, circuit_type.initial_depth
                ))),
            );

            evm_verify(deployment_code, instances, proof);
        }
        calldata
    }
}

impl<F: Field + PrimeField> CircuitExt<F> for EthBlockHeaderChainCircuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        vec![Self::get_num_instance(self.max_depth)]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![self.instance.to_instance()]
    }
}

// Given
// - a JSON-RPC provider
// - choice of EVM network
// - a range of block numbers
// - a universal trusted setup,
//
// this function will generate a ZK proof for the block header chain between blocks `start_block_number` and `end_block_number` inclusive.
//
// If a proving key is provided, it will be used to generate the proof. Otherwise, a new proving key will be generated.
//
// The SNARK's public instance will include a merkle mountain range up to depth `max_depth`.
//
// This SNARK does not use aggregation: it uses a single `EthBlockHeaderChainCircle` circuit,
// so it may not be suitable for large block ranges.

// Given
// - a JSON-RPC provider
// - choice of EVM network
// - a range of block numbers
// - a universal trusted setup,
//
// this function will generate a ZK proof for the block header chain between blocks `start_block_number` and `end_block_number` inclusive. The public instances are NOT finalized,
// as the merkle mountain range is not fully computed.
//
// If a proving key is provided, it will be used to generate the proof. Otherwise, a new proving key will be generated.
//
// This SNARK uses recursive aggregation between depth `max_depth` and `initial_depth + 1`. At `initial_depth` it falls back to the `EthBlockHeaderChainCircle` circuit.
// At each depth, it will try to load snarks of the previous depth from disk, and if it can't find them, it will generate them.

impl CircuitExt<Fr> for EthBlockHeaderChainAggregationCircuit {
    fn num_instance(&self) -> Vec<usize> {
        vec![4 * LIMBS + Self::get_num_instance(self.max_depth, self.initial_depth)]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instance()]
    }
}

// Given
// - a JSON-RPC provider
// - choice of EVM network
// - a range of block numbers
// - a universal trusted setup,
//
// this function will generate a ZK proof for the block header chain between blocks `start_block_number` and `end_block_number` inclusive. The public output is FINALIZED, with
// a complete merkle mountain range.
//
// If a proving key is provided, it will be used to generate the proof. Otherwise, a new proving key will be generated.
//
// This SNARK uses recursive aggregation between depth `max_depth` and `initial_depth + 1`. At `initial_depth` it falls back to the `EthBlockHeaderChainCircle` circuit.
// At each depth, it will try to load snarks of the previous depth from disk, and if it can't find them, it will generate them.
//
// Note: we assume that `params` is the correct size for the circuit.

impl CircuitExt<Fr> for EthBlockHeaderChainFinalAggregationCircuit {
    fn num_instance(&self) -> Vec<usize> {
        vec![4 * LIMBS + Self::get_num_instance(self.0.max_depth)]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instance()]
    }
}

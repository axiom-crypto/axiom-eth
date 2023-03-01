use super::{
    aggregation::{
        EthBlockHeaderChainAggregationCircuit, EthBlockHeaderChainFinalAggregationCircuit,
    },
    EthBlockHeaderChainCircuit,
};
use crate::{
    providers::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL},
    rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder},
    util::{AggregationConfigPinning, EthConfigPinning},
    Network, ETH_LOOKUP_BITS,
};
use core::cmp::min;
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::builder::CircuitBuilderStage,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{Circuit, ProvingKey, VerifyingKey},
        poly::kzg::commitment::ParamsKZG,
    },
    utils::fs::{gen_srs, read_params},
};
use serde_json::to_writer_pretty;
#[cfg(feature = "evm")]
use snark_verifier_sdk::evm::{gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk, read_snark},
    read_pk, CircuitExt, Snark, SHPLONK,
};
use std::{collections::HashMap, env::var, fs::File, path::Path};

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

/// The public/private inputs for various circuits.
/// These are used to create a circuit later (it is debatable whether these should be called circuits at all).
#[derive(Clone, Debug)]
pub enum AnyCircuit {
    Initial(EthBlockHeaderChainCircuit<Fr>),
    Intermediate(EthBlockHeaderChainAggregationCircuit),
    Final(EthBlockHeaderChainFinalAggregationCircuit),
    ForEvm(Vec<Snark>),
}

pub struct Sequencer {
    pub pkeys: HashMap<CircuitType, ProvingKey<G1Affine>>,
    pub params_k: HashMap<CircuitType, u32>,
    pub params: HashMap<u32, ParamsKZG<Bn256>>,
    // pub rng: ChaCha20Rng,
    pub provider: Provider<Http>,
    pub network: Network,
    read_only: bool,
}

impl Sequencer {
    pub fn new(network: Network, read_only: bool) -> Self {
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
            read_only,
        }
    }

    /// Loads environmental variables and returns the degree of the circuit and pinning.
    pub fn set_env(&self, circuit_type: CircuitType) -> (u32, RlcThreadBreakPoints) {
        let network = self.network;
        let CircuitType { depth, initial_depth, finality } = circuit_type;
        let fname_prefix = if depth == initial_depth {
            format!("configs/headers/{network}_{depth}")
        } else {
            format!("configs/headers/{network}_{depth}_{initial_depth}")
        };
        if depth == initial_depth {
            let pinning = EthConfigPinning::from_path(format!("{fname_prefix}.json"));
            (pinning.params.degree, pinning.load())
        } else {
            match finality {
                Finality::None => {
                    let pinning =
                        AggregationConfigPinning::from_path(format!("{fname_prefix}.json"));
                    (pinning.params.degree, pinning.load())
                }
                Finality::Merkle => {
                    let pinning = EthConfigPinning::from_path(format!("{fname_prefix}_final.json"));
                    (pinning.params.degree, pinning.load())
                }
                Finality::Evm(round) => {
                    let pinning = AggregationConfigPinning::from_path(format!(
                        "{fname_prefix}_for_evm_{round}.json"
                    ));
                    (pinning.params.degree, pinning.load())
                }
            }
        }
    }

    /// Read (or generate) the universal trusted setup by reading configuration file.
    /// Loads environmental variables and returns the degree of the circuit and pinning.
    pub fn get_params(&mut self, circuit_type: CircuitType) -> (u32, RlcThreadBreakPoints) {
        let (k, break_points) = self.set_env(circuit_type);
        let read_only = self.read_only;
        self.params.entry(k).or_insert_with(|| if read_only { read_params(k) } else { gen_srs(k) });
        self.params_k.insert(circuit_type, k);
        (k, break_points)
    }

    // auto-update config parameter json files when read_only = false
    fn update_config(&self, circuit_type: CircuitType, break_points: RlcThreadBreakPoints) {
        let network = self.network;
        let CircuitType { depth, initial_depth, finality } = circuit_type;
        let fname_prefix = if depth == initial_depth {
            format!("configs/headers/{network}_{depth}")
        } else {
            format!("configs/headers/{network}_{depth}_{initial_depth}")
        };
        if depth == initial_depth {
            let pinning = EthConfigPinning::from_var(break_points);
            to_writer_pretty(File::create(format!("{fname_prefix}.json")).unwrap(), &pinning)
                .unwrap();
        } else {
            match finality {
                Finality::None => {
                    let pinning = AggregationConfigPinning::from_var(break_points.gate);
                    to_writer_pretty(
                        File::create(format!("{fname_prefix}.json")).unwrap(),
                        &pinning,
                    )
                    .unwrap();
                }
                Finality::Merkle => {
                    let pinning = EthConfigPinning::from_var(break_points);
                    to_writer_pretty(
                        File::create(format!("{fname_prefix}_final.json")).unwrap(),
                        &pinning,
                    )
                    .unwrap();
                }
                Finality::Evm(round) => {
                    let pinning = AggregationConfigPinning::from_var(break_points.gate);
                    to_writer_pretty(
                        File::create(format!("{fname_prefix}_for_evm_{round}.json")).unwrap(),
                        &pinning,
                    )
                    .unwrap();
                }
            }
        };
    }

    // recursively generates necessary snarks to create circuit
    pub fn get_circuit(&mut self, task: Task) -> AnyCircuit {
        let Task { start, end, circuit_type } = task;
        let CircuitType { depth, initial_depth, finality } = circuit_type;
        assert!(end - start < 1 << depth);
        if depth == initial_depth {
            // set environmental vars
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
            match finality {
                Finality::None => {
                    let circuit = EthBlockHeaderChainAggregationCircuit::new(
                        snarks,
                        end - start + 1,
                        depth,
                        initial_depth,
                    );
                    AnyCircuit::Intermediate(circuit)
                }
                Finality::Merkle => {
                    let circuit = EthBlockHeaderChainFinalAggregationCircuit::new(
                        snarks,
                        end - start + 1,
                        depth,
                        initial_depth,
                    );
                    AnyCircuit::Final(circuit)
                }
                Finality::Evm(_) => AnyCircuit::ForEvm(snarks),
            }
        }
    }

    // recursively generates necessary circuits and snarks to create snark
    pub fn get_snark(&mut self, task: Task) -> Snark {
        let network = self.network;
        if let Ok(snark) = task.read_snark(network) {
            return snark;
        }
        let circuit_input = self.get_circuit(task);
        let circuit_type = task.circuit_type;
        let (k, mut break_points) = self.get_params(circuit_type);
        let params = &self.params[&k];
        let pk_name = circuit_type.pkey_name(network);
        let pk_path = Some(Path::new(&pk_name));
        let lookup_bits =
            var("LOOKUP_BITS").unwrap_or_else(|_| ETH_LOOKUP_BITS.to_string()).parse().unwrap();
        let read_only = self.read_only;

        let pk = if let Some(pk) = self.pkeys.get(&circuit_type) {
            pk
        } else {
            // as you can see we do the same thing for each circuit, but because `Circuit` is
            // not an object-safe trait we can't put it in a `Box`
            let pk = match circuit_input.clone() {
                AnyCircuit::Initial(input) => {
                    let circuit = input.create_circuit(RlcThreadBuilder::keygen(), None);
                    if read_only {
                        readonly_pk(&pk_name, &circuit)
                    } else {
                        let pk = gen_pk(params, &circuit, pk_path);
                        // if pk exists already then no break points are generated, so we should use existing break points
                        let tmp = circuit.circuit.break_points.take();
                        if tmp != Default::default() {
                            break_points = tmp;
                        }
                        pk
                    }
                }
                AnyCircuit::Intermediate(input) => {
                    let circuit = input.create_circuit(
                        CircuitBuilderStage::Keygen,
                        None,
                        lookup_bits,
                        params,
                    );
                    if read_only {
                        readonly_pk(&pk_name, &circuit)
                    } else {
                        let pk = gen_pk(params, &circuit, pk_path);
                        let tmp = circuit.inner.circuit.0.break_points.take();
                        if !tmp.is_empty() && !tmp[0].is_empty() {
                            break_points.gate = tmp;
                        }
                        pk
                    }
                }
                AnyCircuit::Final(input) => {
                    let circuit = input.create_circuit(
                        CircuitBuilderStage::Keygen,
                        None,
                        lookup_bits,
                        params,
                    );
                    if read_only {
                        readonly_pk(&pk_name, &circuit)
                    } else {
                        let pk = gen_pk(params, &circuit, pk_path);
                        let tmp = circuit.circuit.break_points.take();
                        if tmp != Default::default() {
                            break_points = tmp;
                        }
                        pk
                    }
                }
                AnyCircuit::ForEvm(snarks) => {
                    let circuit = AggregationCircuit::public::<SHPLONK>(
                        CircuitBuilderStage::Keygen,
                        None,
                        lookup_bits,
                        params,
                        snarks,
                        true,
                    );
                    if read_only {
                        readonly_pk(&pk_name, &circuit)
                    } else {
                        circuit.config(
                            k,
                            Some(
                                var("MINIMUM_ROWS")
                                    .unwrap_or_else(|_| "10".to_string())
                                    .parse()
                                    .unwrap(),
                            ),
                        );
                        let pk = gen_pk(params, &circuit, pk_path);
                        let tmp = circuit.inner.circuit.0.break_points.take();
                        if !tmp.is_empty() && !tmp[0].is_empty() {
                            break_points.gate = tmp;
                        }
                        pk
                    }
                }
            };
            self.pkeys.insert(circuit_type, pk);
            if read_only {
                // for extra safety, to make sure pk auto-config did not change the config parameters, we reload env vars
                self.set_env(circuit_type);
            }
            self.pkeys.get(&circuit_type).unwrap()
        };
        if !read_only {
            self.update_config(circuit_type, break_points.clone());
        }
        let snark_path = Some(task.snark_name(network));
        match circuit_input {
            AnyCircuit::Initial(input) => {
                let circuit = input.create_circuit(RlcThreadBuilder::prover(), Some(break_points));
                gen_snark_shplonk(params, pk, circuit, snark_path)
            }
            AnyCircuit::Intermediate(input) => {
                let circuit = input.create_circuit(
                    CircuitBuilderStage::Prover,
                    Some(break_points.gate),
                    lookup_bits,
                    params,
                );
                gen_snark_shplonk(params, pk, circuit, snark_path)
            }
            AnyCircuit::Final(input) => {
                let circuit = input.create_circuit(
                    CircuitBuilderStage::Prover,
                    Some(break_points),
                    lookup_bits,
                    params,
                );
                gen_snark_shplonk(params, pk, circuit, snark_path)
            }
            AnyCircuit::ForEvm(snarks) => {
                let circuit = AggregationCircuit::public::<SHPLONK>(
                    // shplonk is for previous round of snarks
                    CircuitBuilderStage::Prover,
                    Some(break_points.gate),
                    lookup_bits,
                    params,
                    snarks,
                    true,
                );
                gen_snark_shplonk(params, pk, circuit, snark_path)
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
        let circuit_input = self.get_circuit(task);
        let (k, mut break_points) = self.get_params(circuit_type);
        let params = &self.params[&k];
        let pk_name = circuit_type.pkey_name(self.network);
        let pk_path = Some(Path::new(&pk_name));
        let lookup_bits =
            var("LOOKUP_BITS").unwrap_or_else(|_| ETH_LOOKUP_BITS.to_string()).parse().unwrap();
        let read_only = self.read_only;
        if let AnyCircuit::ForEvm(snarks) = circuit_input {
            let get_pk = self.pkeys.get(&circuit_type).is_none();
            let mut deployment_code = None;
            if get_pk || generate_smart_contract {
                let circuit = AggregationCircuit::public::<SHPLONK>(
                    CircuitBuilderStage::Keygen,
                    None,
                    lookup_bits,
                    params,
                    snarks.clone(),
                    true,
                );
                circuit.config(
                    k,
                    Some(var("MINIMUM_ROWS").unwrap_or_else(|_| "10".to_string()).parse().unwrap()),
                );
                if get_pk {
                    let pk = if read_only {
                        readonly_pk(&pk_name, &circuit)
                    } else {
                        let pk = gen_pk(params, &circuit, pk_path);
                        let tmp = circuit.inner.circuit.0.break_points.take();
                        if !tmp.is_empty() && !tmp[0].is_empty() {
                            break_points.gate = tmp;
                        }
                        pk
                    };
                    self.pkeys.insert(circuit_type, pk);
                }
                if generate_smart_contract {
                    let pk = self.pkeys.get(&circuit_type).unwrap();
                    let deploy_code = custom_gen_evm_verifier_shplonk(
                        params,
                        pk.get_vk(),
                        &circuit,
                        Some(Path::new(&format!(
                            "data/headers/{}_{}_{}.yul",
                            self.network, circuit_type.depth, circuit_type.initial_depth
                        ))),
                    );
                    deployment_code = Some(deploy_code);
                }
            }
            let pk = self.pkeys.get(&circuit_type).unwrap();
            let circuit = AggregationCircuit::public::<SHPLONK>(
                CircuitBuilderStage::Prover,
                Some(break_points.gate),
                lookup_bits,
                params,
                snarks,
                true,
            );
            write_calldata_generic(params, pk, circuit, &fname, deployment_code)
        } else {
            unreachable!()
        }
    }
}

#[cfg(feature = "evm")]
fn write_calldata_generic<ConcreteCircuit: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: ConcreteCircuit,
    path: impl AsRef<Path>,
    deployment_code: Option<Vec<u8>>,
) -> Vec<u8> {
    #[allow(unused_imports)]
    use ethers_core::utils::hex;
    use snark_verifier::loader::evm::encode_calldata;
    use snark_verifier_sdk::evm::evm_verify;
    use std::fs;

    let instances = circuit.instances();
    let proof = gen_evm_proof_shplonk(params, pk, circuit, instances.clone());
    let calldata = encode_calldata(&instances, &proof);
    fs::write(path, hex::encode(&calldata)).expect("write calldata should not fail");
    if let Some(deployment_code) = deployment_code {
        evm_verify(deployment_code, instances, proof);
    }
    calldata
}

// need to trick rust into inferring type of the circuit because `C` involves closures
// this is not ideal...
fn readonly_pk<C: Circuit<Fr>>(fname: &str, _: &C) -> ProvingKey<G1Affine> {
    read_pk::<C>(Path::new(fname)).expect("proving key should exist")
}

// also for type inference
pub fn custom_gen_evm_verifier_shplonk<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    circuit: &C,
    path: Option<&Path>,
) -> Vec<u8> {
    gen_evm_verifier_shplonk::<C>(params, vk, circuit.num_instance(), path)
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

use super::{
    aggregation::{
        EthBlockHeaderChainAggregationCircuit, EthBlockHeaderChainFinalAggregationCircuit,
    },
    EthBlockHeaderChainCircuit,
};
use crate::{
    keccak::FnSynthesize,
    providers::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL},
    rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder},
    util::{AggregationConfigPinning, EthConfigPinning, Halo2ConfigPinning},
    EthCircuitBuilder, Field, Network,
};
use core::cmp::min;
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::builder::{CircuitBuilderStage, MultiPhaseThreadBreakPoints},
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{Circuit, ProvingKey, VerifyingKey},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
    utils::fs::{gen_srs, read_params},
};
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

/// Aggregates snarks and re-exposes previous public inputs.
///
/// If `has_prev_accumulators` is true, then it assumes all previous snarks are already aggregation circuits and does not re-expose the old accumulators as public inputs.
#[derive(Clone, Debug)]
pub struct PublicAggregationCircuit {
    pub snarks: Vec<Snark>,
    pub has_prev_accumulators: bool,
}

/// The public/private inputs for various circuits.
/// These are used to create a circuit later (it is debatable whether these should be called circuits at all).
#[derive(Clone, Debug)]
pub enum AnyCircuit {
    Initial(EthBlockHeaderChainCircuit<Fr>),
    Intermediate(EthBlockHeaderChainAggregationCircuit),
    Final(EthBlockHeaderChainFinalAggregationCircuit),
    ForEvm(PublicAggregationCircuit),
}

impl AnyCircuit {
    fn read_or_create_pk(
        self,
        params: &ParamsKZG<Bn256>,
        pk_path: impl AsRef<Path>,
        pinning_path: impl AsRef<Path>,
        read_only: bool,
    ) -> ProvingKey<G1Affine> {
        // does almost the same thing for each circuit type; don't know how to get around this with rust
        match self {
            AnyCircuit::Initial(pre_circuit) => {
                pre_circuit.read_or_create_pk(params, pk_path, pinning_path, read_only)
            }
            AnyCircuit::Intermediate(pre_circuit) => {
                pre_circuit.read_or_create_pk(params, pk_path, pinning_path, read_only)
            }
            AnyCircuit::Final(pre_circuit) => {
                pre_circuit.read_or_create_pk(params, pk_path, pinning_path, read_only)
            }
            AnyCircuit::ForEvm(pre_circuit) => {
                pre_circuit.read_or_create_pk(params, pk_path, pinning_path, read_only)
            }
        }
    }

    fn gen_snark_shplonk(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: Option<impl AsRef<Path>>,
    ) -> Snark {
        match self {
            AnyCircuit::Initial(pre_circuit) => {
                pre_circuit.gen_snark_shplonk(params, pk, pinning_path, path)
            }
            AnyCircuit::Intermediate(pre_circuit) => {
                pre_circuit.gen_snark_shplonk(params, pk, pinning_path, path)
            }
            AnyCircuit::Final(pre_circuit) => {
                pre_circuit.gen_snark_shplonk(params, pk, pinning_path, path)
            }
            AnyCircuit::ForEvm(pre_circuit) => {
                pre_circuit.gen_snark_shplonk(params, pk, pinning_path, path)
            }
        }
    }
}

pub struct Sequencer {
    pub pkeys: HashMap<CircuitType, ProvingKey<G1Affine>>,
    pub params_k: HashMap<CircuitType, u32>,
    pub params: HashMap<u32, ParamsKZG<Bn256>>,
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

    /// The path to the file with the circuit configuration pinning.
    pub fn pinning_path(&self, circuit_type: CircuitType) -> String {
        let network = self.network;
        let CircuitType { depth, initial_depth, finality } = circuit_type;
        let fname_prefix = if depth == initial_depth {
            format!("configs/headers/{network}_{depth}")
        } else {
            format!("configs/headers/{network}_{depth}_{initial_depth}")
        };
        if depth == initial_depth {
            format!("{fname_prefix}.json")
        } else {
            match finality {
                Finality::None => {
                    format!("{fname_prefix}.json")
                }
                Finality::Merkle => {
                    format!("{fname_prefix}_final.json")
                }
                Finality::Evm(round) => {
                    format!("{fname_prefix}_for_evm_{round}.json")
                }
            }
        }
    }

    /// Returns the degree of the circuit from file
    pub fn get_degree(&self, circuit_type: CircuitType) -> u32 {
        let path = self.pinning_path(circuit_type);
        let CircuitType { depth, initial_depth, finality } = circuit_type;
        if depth == initial_depth {
            EthConfigPinning::from_path(path).params.degree
        } else {
            match finality {
                Finality::None | Finality::Evm(_) => {
                    AggregationConfigPinning::from_path(path).params.degree
                }
                Finality::Merkle => EthConfigPinning::from_path(path).params.degree,
            }
        }
    }

    /// Read (or generate) the universal trusted setup by reading configuration file.
    /// Loads environmental variables and returns the degree of the circuit and pinning.
    pub fn get_params(&mut self, circuit_type: CircuitType) -> u32 {
        let k = self.get_degree(circuit_type);
        let read_only = self.read_only;
        self.params.entry(k).or_insert_with(|| if read_only { read_params(k) } else { gen_srs(k) });
        self.params_k.insert(circuit_type, k);
        k
    }

    // recursively generates necessary snarks to create circuit
    pub fn get_circuit(&mut self, task: Task) -> AnyCircuit {
        let Task { start, end, circuit_type } = task;
        let CircuitType { depth, initial_depth, finality } = circuit_type;
        assert!(end - start < 1 << depth);
        if depth == initial_depth {
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
                Finality::Evm(_) => AnyCircuit::ForEvm(PublicAggregationCircuit {
                    snarks,
                    has_prev_accumulators: true,
                }),
            }
        }
    }

    // recursively generates necessary circuits and snarks to create snark
    pub fn get_snark(&mut self, task: Task) -> Snark {
        let network = self.network;
        if let Ok(snark) = task.read_snark(network) {
            return snark;
        }
        let read_only = self.read_only;
        let circuit_type = task.circuit_type;
        let pre_circuit = self.get_circuit(task);

        let k = self.get_params(circuit_type);
        let params = &self.params[&k];

        let pk_name = circuit_type.pkey_name(network);
        let pinning_path = self.pinning_path(circuit_type);

        let pk = if let Some(pk) = self.pkeys.get(&circuit_type) {
            pk
        } else {
            let pk =
                pre_circuit.clone().read_or_create_pk(params, pk_name, &pinning_path, read_only);
            self.pkeys.insert(circuit_type, pk);
            &self.pkeys[&circuit_type]
        };
        let snark_path = Some(task.snark_name(network));
        pre_circuit.gen_snark_shplonk(params, pk, &pinning_path, snark_path)
    }

    #[cfg(feature = "evm")]
    pub fn get_calldata(&mut self, task: Task, generate_smart_contract: bool) -> Vec<u8> {
        let network = self.network;
        let Task { start, end, circuit_type } = task;
        let CircuitType { depth, initial_depth, finality: _ } = circuit_type;
        assert!(matches!(circuit_type.finality, Finality::Evm(_)));
        let fname = format!(
            "data/headers/{network}_{depth}_{initial_depth}_{start:06x}_{end:06x}.calldata",
        );
        if let Ok(calldata) = std::fs::read(&fname) {
            return calldata;
        }
        let read_only = self.read_only;

        let pre_circuit = self.get_circuit(task);
        let k = self.get_params(circuit_type);
        let params = &self.params[&k];

        let pk_name = circuit_type.pkey_name(self.network);
        let pinning_path = self.pinning_path(circuit_type);

        if let AnyCircuit::ForEvm(pre_circuit) = pre_circuit {
            let pk = self.pkeys.entry(circuit_type).or_insert_with(|| {
                pre_circuit.clone().read_or_create_pk(params, pk_name, &pinning_path, read_only)
            });
            let mut deployment_code = None;
            if generate_smart_contract {
                let circuit =
                    pre_circuit.clone().create_circuit(CircuitBuilderStage::Keygen, None, params);
                let deploy_code = custom_gen_evm_verifier_shplonk(
                    params,
                    pk.get_vk(),
                    &circuit,
                    Some(format!("data/headers/{network}_{depth}_{initial_depth}.yul",)),
                );
                deployment_code = Some(deploy_code);
            }
            pre_circuit.gen_calldata(params, pk, pinning_path, fname, deployment_code)
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
fn custom_read_pk<C, P>(fname: P, _: &C) -> ProvingKey<G1Affine>
where
    C: Circuit<Fr>,
    P: AsRef<Path>,
{
    read_pk::<C>(fname.as_ref()).expect("proving key should exist")
}

// also for type inference
pub fn custom_gen_evm_verifier_shplonk<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    circuit: &C,
    path: Option<impl AsRef<Path>>,
) -> Vec<u8> {
    gen_evm_verifier_shplonk::<C>(
        params,
        vk,
        circuit.num_instance(),
        path.as_ref().map(|p| p.as_ref()),
    )
}

pub trait PreCircuit: Sized {
    type Pinning: Halo2ConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<<Self::Pinning as Halo2ConfigPinning>::BreakPoints>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr>;

    /// Reads the proving key for the pre-circuit.
    /// If `read_only` is true, then it is assumed that the proving key exists and can be read from `path` (otherwise the program will panic).
    fn read_pk(self, params: &ParamsKZG<Bn256>, path: impl AsRef<Path>) -> ProvingKey<G1Affine> {
        let circuit = self.create_circuit(CircuitBuilderStage::Keygen, None, params);
        custom_read_pk(path, &circuit)
    }

    fn create_pk(
        self,
        params: &ParamsKZG<Bn256>,
        pinning_path: impl AsRef<Path>,
    ) -> ProvingKey<G1Affine> {
        let circuit = self.create_circuit(CircuitBuilderStage::Keygen, None, params);
        let pk = gen_pk(params, &circuit, None);
        circuit.write_pinning(pinning_path);

        pk
    }

    fn read_or_create_pk(
        self,
        params: &ParamsKZG<Bn256>,
        pk_path: impl AsRef<Path>,
        pinning_path: impl AsRef<Path>,
        read_only: bool,
    ) -> ProvingKey<G1Affine> {
        if read_only {
            self.read_pk(params, pk_path)
        } else {
            self.create_pk(params, pinning_path)
        }
    }

    fn gen_snark_shplonk(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: Option<impl AsRef<Path>>,
    ) -> Snark {
        let pinning = Self::Pinning::from_path(pinning_path);
        let break_points = pinning.break_points();
        let circuit = self.create_circuit(CircuitBuilderStage::Prover, Some(break_points), params);
        gen_snark_shplonk(params, pk, circuit, path)
    }

    #[cfg(feature = "evm")]
    fn gen_calldata(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: impl AsRef<Path>,
        deployment_code: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let pinning = Self::Pinning::from_path(pinning_path);
        let break_points = pinning.break_points();
        let circuit = self.create_circuit(CircuitBuilderStage::Prover, Some(break_points), params);
        write_calldata_generic(params, pk, circuit, path, deployment_code)
    }
}

impl PreCircuit for EthBlockHeaderChainCircuit<Fr> {
    type Pinning = EthConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<RlcThreadBreakPoints>,
        _: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        let builder = match stage {
            CircuitBuilderStage::Prover => RlcThreadBuilder::new(true),
            _ => RlcThreadBuilder::new(false),
        };
        EthBlockHeaderChainCircuit::create_circuit(self, builder, break_points)
    }
}

impl PreCircuit for EthBlockHeaderChainAggregationCircuit {
    type Pinning = AggregationConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        let lookup_bits = var("LOOKUP_BITS").expect("LOOKUP_BITS is not set").parse().unwrap();
        EthBlockHeaderChainAggregationCircuit::create_circuit(
            self,
            stage,
            break_points,
            lookup_bits,
            params,
        )
    }
}

impl PreCircuit for EthBlockHeaderChainFinalAggregationCircuit {
    type Pinning = EthConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<RlcThreadBreakPoints>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        let lookup_bits = var("LOOKUP_BITS").expect("LOOKUP_BITS is not set").parse().unwrap();
        EthBlockHeaderChainFinalAggregationCircuit::create_circuit(
            self,
            stage,
            break_points,
            lookup_bits,
            params,
        )
    }
}

impl PreCircuit for PublicAggregationCircuit {
    type Pinning = AggregationConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        let lookup_bits = var("LOOKUP_BITS").expect("LOOKUP_BITS is not set").parse().unwrap();
        let circuit = AggregationCircuit::public::<SHPLONK>(
            stage,
            break_points,
            lookup_bits,
            params,
            self.snarks,
            self.has_prev_accumulators,
        );
        match stage {
            CircuitBuilderStage::Prover => {}
            _ => {
                circuit.config(
                    params.k(),
                    Some(var("MINIMUM_ROWS").unwrap_or_else(|_| "10".to_string()).parse().unwrap()),
                );
            }
        }
        circuit
    }
}

pub trait PinnableCircuit<F: ff::Field>: CircuitExt<F> {
    type Pinning: Halo2ConfigPinning;

    fn break_points(&self) -> <Self::Pinning as Halo2ConfigPinning>::BreakPoints;

    fn write_pinning(&self, path: impl AsRef<Path>) {
        let break_points = self.break_points();
        let pinning: Self::Pinning = Halo2ConfigPinning::from_var(break_points);
        serde_json::to_writer_pretty(File::create(path).unwrap(), &pinning).unwrap();
    }
}

impl<F: Field, FnPhase1: FnSynthesize<F>> PinnableCircuit<F> for EthCircuitBuilder<F, FnPhase1> {
    type Pinning = EthConfigPinning;

    fn break_points(&self) -> RlcThreadBreakPoints {
        self.circuit.break_points.borrow().clone()
    }
}

impl PinnableCircuit<Fr> for AggregationCircuit {
    type Pinning = AggregationConfigPinning;

    fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        AggregationCircuit::break_points(self)
    }
}

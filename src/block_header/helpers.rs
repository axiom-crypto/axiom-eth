use super::{
    aggregation::{
        EthBlockHeaderChainAggregationCircuit, EthBlockHeaderChainFinalAggregationCircuit,
    },
    EthBlockHeaderChainCircuit,
};
use crate::{
    rlp::builder::RlcThreadBuilder,
    util::{
        circuit::{AnyCircuit, PinnableCircuit},
        circuit::{PreCircuit, PublicAggregationCircuit},
        scheduler::{self, EthScheduler, Scheduler},
        AggregationConfigPinning, EthConfigPinning, Halo2ConfigPinning,
    },
    Network,
};
use core::cmp::min;
use halo2_base::{
    gates::builder::CircuitBuilderStage,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::ProvingKey,
        poly::kzg::commitment::ParamsKZG,
    },
};
use snark_verifier_sdk::Snark;
use std::{env::var, path::Path};

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
    pub network: Network,
    pub depth: usize,
    pub initial_depth: usize,
    pub finality: Finality,
}

impl CircuitType {
    pub fn new(depth: usize, initial_depth: usize, finality: Finality, network: Network) -> Self {
        Self { depth, initial_depth, finality, network }
    }

    pub fn prev(&self) -> Self {
        assert!(self.depth != self.initial_depth, "Trying to call prev on initial circuit");
        match self.finality {
            Finality::None | Finality::Merkle => {
                Self::new(self.depth - 1, self.initial_depth, Finality::None, self.network)
            }
            Finality::Evm(round) => {
                if round == 0 {
                    Self::new(self.depth, self.initial_depth, Finality::Merkle, self.network)
                } else {
                    Self::new(
                        self.depth,
                        self.initial_depth,
                        Finality::Evm(round - 1),
                        self.network,
                    )
                }
            }
        }
    }

    pub fn fname_prefix(&self) -> String {
        if self.depth == self.initial_depth {
            format!("{}_{}", self.network, self.depth)
        } else {
            format!("{}_{}_{}", self.network, self.depth, self.initial_depth)
        }
    }

    pub fn fname_suffix(&self) -> String {
        match self.finality {
            Finality::None => "".to_string(),
            Finality::Merkle => "_final".to_string(),
            Finality::Evm(round) => format!("_for_evm_{round}"),
        }
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
}

impl scheduler::Task for Task {
    type CircuitType = CircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        self.circuit_type
    }
    fn type_name(circuit_type: Self::CircuitType) -> String {
        format!("{}{}", circuit_type.fname_prefix(), circuit_type.fname_suffix())
    }
    fn name(&self) -> String {
        format!(
            "{}_{:06x}_{:06x}{}",
            self.circuit_type.fname_prefix(),
            self.start,
            self.end,
            self.circuit_type.fname_suffix()
        )
    }
    fn dependencies(&self) -> Vec<Self> {
        let Task { start, end, circuit_type } = *self;
        let CircuitType { network: _, depth, initial_depth, finality: _ } = circuit_type;
        assert!(end - start < 1 << depth);
        if depth == initial_depth {
            vec![]
        } else {
            let prev_type = circuit_type.prev();
            let prev_depth = prev_type.depth;
            (start..=end)
                .step_by(1 << prev_depth)
                .map(|i| Task::new(i, min(end, i + (1 << prev_depth) - 1), prev_type))
                .collect()
        }
    }
}

/// The public/private inputs for various circuits.
// This is an enum of `PreCircuit`s.
// Perhaps a macro should be used instead. Rust traits do not allow a single type to output different kinds of `PreCircuit`s.
#[derive(Clone, Debug)]
pub enum CircuitRouter {
    Initial(EthBlockHeaderChainCircuit<Fr>),
    Intermediate(EthBlockHeaderChainAggregationCircuit),
    Final(EthBlockHeaderChainFinalAggregationCircuit),
    ForEvm(PublicAggregationCircuit),
}

pub type BlockHeaderScheduler = EthScheduler<Task>;

impl Scheduler for BlockHeaderScheduler {
    type Task = Task;
    type CircuitRouter = CircuitRouter;

    fn get_degree(&self, circuit_type: CircuitType) -> u32 {
        if let Some(k) = self.degree.read().unwrap().get(&circuit_type) {
            return *k;
        }
        let path = self.pinning_path(circuit_type);
        let CircuitType { network: _, depth, initial_depth, finality } = circuit_type;
        let k = if depth == initial_depth {
            EthConfigPinning::from_path(path).params.degree
        } else {
            match finality {
                Finality::None | Finality::Evm(_) => {
                    AggregationConfigPinning::from_path(path).params.degree
                }
                Finality::Merkle => EthConfigPinning::from_path(path).params.degree,
            }
        };
        self.degree.write().unwrap().insert(circuit_type, k);
        k
    }

    fn get_circuit(&self, task: Task, mut snarks: Vec<Snark>) -> CircuitRouter {
        let Task { start, end, circuit_type } = task;
        let CircuitType { network, depth, initial_depth, finality } = circuit_type;
        assert_eq!(network, self.network);
        assert!(end - start < 1 << depth);
        if depth == initial_depth {
            let circuit = EthBlockHeaderChainCircuit::from_provider(
                &self.provider,
                network,
                start,
                end - start + 1,
                depth,
            );
            CircuitRouter::Initial(circuit)
        } else {
            assert!(!snarks.is_empty());
            match finality {
                Finality::None => {
                    if snarks.len() != 2 {
                        snarks.resize(2, snarks[0].clone()); // dummy snark
                    }
                    let circuit = EthBlockHeaderChainAggregationCircuit::new(
                        snarks,
                        end - start + 1,
                        depth,
                        initial_depth,
                    );
                    CircuitRouter::Intermediate(circuit)
                }
                Finality::Merkle => {
                    if snarks.len() != 2 {
                        snarks.resize(2, snarks[0].clone()); // dummy snark
                    }
                    let circuit = EthBlockHeaderChainFinalAggregationCircuit::new(
                        snarks,
                        end - start + 1,
                        depth,
                        initial_depth,
                    );
                    CircuitRouter::Final(circuit)
                }
                Finality::Evm(_) => {
                    assert_eq!(snarks.len(), 1); // currently just passthrough
                    CircuitRouter::ForEvm(PublicAggregationCircuit {
                        snarks,
                        has_prev_accumulators: true,
                    })
                }
            }
        }
    }
}

impl PreCircuit for EthBlockHeaderChainCircuit<Fr> {
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
        let break_points = pinning.map(|p| p.break_points());
        EthBlockHeaderChainCircuit::create_circuit(self, builder, break_points)
    }
}

impl PreCircuit for EthBlockHeaderChainAggregationCircuit {
    type Pinning = AggregationConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        let lookup_bits = var("LOOKUP_BITS").expect("LOOKUP_BITS is not set").parse().unwrap();
        let break_points = pinning.map(|p| p.break_points());
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
        pinning: Option<Self::Pinning>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        let lookup_bits = var("LOOKUP_BITS").expect("LOOKUP_BITS is not set").parse().unwrap();
        let break_points = pinning.map(|p| p.break_points());
        EthBlockHeaderChainFinalAggregationCircuit::create_circuit(
            self,
            stage,
            break_points,
            lookup_bits,
            params,
        )
    }
}

// just copy/paste.. cannot find better way right now
impl AnyCircuit for CircuitRouter {
    fn read_or_create_pk(
        self,
        params: &ParamsKZG<Bn256>,
        pk_path: impl AsRef<Path>,
        pinning_path: impl AsRef<Path>,
        read_only: bool,
    ) -> ProvingKey<G1Affine> {
        // does almost the same thing for each circuit type; don't know how to get around this with rust
        match self {
            Self::Initial(pre_circuit) => {
                pre_circuit.read_or_create_pk(params, pk_path, pinning_path, read_only)
            }
            Self::Intermediate(pre_circuit) => {
                pre_circuit.read_or_create_pk(params, pk_path, pinning_path, read_only)
            }
            Self::Final(pre_circuit) => {
                pre_circuit.read_or_create_pk(params, pk_path, pinning_path, read_only)
            }
            Self::ForEvm(pre_circuit) => {
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
            Self::Initial(pre_circuit) => {
                pre_circuit.gen_snark_shplonk(params, pk, pinning_path, path)
            }
            Self::Intermediate(pre_circuit) => {
                pre_circuit.gen_snark_shplonk(params, pk, pinning_path, path)
            }
            Self::Final(pre_circuit) => {
                pre_circuit.gen_snark_shplonk(params, pk, pinning_path, path)
            }
            Self::ForEvm(pre_circuit) => {
                pre_circuit.gen_snark_shplonk(params, pk, pinning_path, path)
            }
        }
    }

    fn gen_evm_verifier_shplonk(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        yul_path: impl AsRef<Path>,
    ) -> Vec<u8> {
        match self {
            Self::Initial(pre_circuit) => {
                pre_circuit.gen_evm_verifier_shplonk(params, pk, yul_path)
            }
            Self::Intermediate(pre_circuit) => {
                pre_circuit.gen_evm_verifier_shplonk(params, pk, yul_path)
            }
            Self::Final(pre_circuit) => pre_circuit.gen_evm_verifier_shplonk(params, pk, yul_path),
            Self::ForEvm(pre_circuit) => pre_circuit.gen_evm_verifier_shplonk(params, pk, yul_path),
        }
    }

    fn gen_calldata(
        self,
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        pinning_path: impl AsRef<Path>,
        path: impl AsRef<Path>,
        deployment_code: Option<Vec<u8>>,
    ) -> Vec<u8> {
        match self {
            Self::Initial(pre_circuit) => {
                pre_circuit.gen_calldata(params, pk, pinning_path, path, deployment_code)
            }
            Self::Intermediate(pre_circuit) => {
                pre_circuit.gen_calldata(params, pk, pinning_path, path, deployment_code)
            }
            Self::Final(pre_circuit) => {
                pre_circuit.gen_calldata(params, pk, pinning_path, path, deployment_code)
            }
            Self::ForEvm(pre_circuit) => {
                pre_circuit.gen_calldata(params, pk, pinning_path, path, deployment_code)
            }
        }
    }
}

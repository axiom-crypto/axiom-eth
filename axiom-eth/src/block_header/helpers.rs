use super::{
    aggregation::{
        EthBlockHeaderChainAggregationCircuit, EthBlockHeaderChainFinalAggregationCircuit,
    },
    EthBlockHeaderChainCircuit,
};
use crate::{
    util::{
        circuit::{AnyCircuit, PinnableCircuit},
        circuit::{PreCircuit, PublicAggregationCircuit},
        scheduler::{self, EthScheduler, Scheduler},
        AggregationConfigPinning, EthConfigPinning, Halo2ConfigPinning,
    },
    AggregationPreCircuit, Network,
};
use any_circuit_derive::AnyCircuit;
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

impl scheduler::CircuitType for CircuitType {
    fn name(&self) -> String {
        format!("{}{}", self.fname_prefix(), self.fname_suffix())
    }

    fn get_degree_from_pinning(&self, path: impl AsRef<Path>) -> u32 {
        let CircuitType { network: _, depth, initial_depth, finality } = self;
        if depth == initial_depth {
            EthConfigPinning::from_path(path).degree()
        } else {
            match finality {
                Finality::None | Finality::Evm(_) => {
                    AggregationConfigPinning::from_path(path).degree()
                }
                Finality::Merkle => EthConfigPinning::from_path(path).degree(),
            }
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
// We implement `AnyCircuit` for `CircuitRouter` by passing through the implementations from each enum variant using a procedural macro.
// This is because Rust traits do not allow a single type to output different kinds of `PreCircuit`s.
#[derive(Clone, Debug, AnyCircuit)]
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
                    CircuitRouter::ForEvm(PublicAggregationCircuit::new(
                        snarks.into_iter().map(|snark| (snark, true)).collect(),
                    ))
                }
            }
        }
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
        // look for lookup_bits either from pinning, if available, or from env var
        let lookup_bits = pinning
            .as_ref()
            .map(|p| p.params.lookup_bits)
            .or_else(|| var("LOOKUP_BITS").map(|v| v.parse().unwrap()).ok())
            .expect("LOOKUP_BITS is not set");
        let break_points = pinning.map(|p| p.break_points());
        AggregationPreCircuit::create_circuit(self, stage, break_points, lookup_bits, params)
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
        // look for lookup_bits either from pinning, if available, or from env var
        let lookup_bits = pinning
            .as_ref()
            .map(|p| p.params.lookup_bits.unwrap())
            .or_else(|| var("LOOKUP_BITS").map(|v| v.parse().unwrap()).ok())
            .expect("LOOKUP_BITS is not set");
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

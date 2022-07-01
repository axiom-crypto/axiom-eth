use std::{hash::Hash, path::Path};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    util::{scheduler, AggregationConfigPinning, EthConfigPinning, Halo2ConfigPinning},
    Network,
};

/// Schema to aggregate the proof of 2<sup>total_arity</sup> rows of either a single response column or a response table.
///
/// Let `n = start_arity` and `N = total_arity`. We recursively prove snarks for 2<sup>n</sup>, 2<sup>n</sup>, 2<sup>n + 1</sup>, ..., 2<sup>N - 1</sup> entries, for a total of 2<sup>N</sup> entries.
///
/// At level `i`, we prove 2<sup>n + max(0, i - 1)</sup> entries in a single snark and then recursively aggregate this snark with the snark for levels `> i`. The last level is level `N - n`.
///
/// At level `> 0` we use `PublicAggregationCircuit` for the aggregation. At level `0` we use `{Merkle,Poseidon}AggregationCircuit` to compute Merkle tree roots.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExponentialSchema {
    pub start_arity: usize,
    pub total_arity: usize,
    pub level: usize,
}

impl ExponentialSchema {
    pub fn new(start_arity: usize, total_arity: usize, level: usize) -> Self {
        assert!(start_arity <= total_arity);
        assert!(level <= total_arity - start_arity);
        Self { start_arity, total_arity, level }
    }

    pub fn next(&self) -> Self {
        Self::new(self.start_arity, self.total_arity, self.level + 1)
    }

    pub fn level_arity(&self) -> usize {
        self.start_arity + self.level.saturating_sub(1)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitialCircuitType {
    Account,
    Storage,
    RowConsistency,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseCircuitType {
    pub initial_type: InitialCircuitType,
    pub schema: ExponentialSchema,
    pub aggregate: bool,
}

impl scheduler::CircuitType for ResponseCircuitType {
    fn name(&self) -> String {
        // mostly for human readability, does not need to be collision resistant (we just manually delete old pkeys)
        let prefix = match self.initial_type {
            InitialCircuitType::Account => "account".to_string(),
            InitialCircuitType::Storage => "storage".to_string(),
            InitialCircuitType::RowConsistency => "row".to_string(),
        };
        if !self.aggregate {
            format!("{prefix}_{}", self.schema.level_arity())
        } else {
            format!(
                "{prefix}_{}_{}_{}",
                self.schema.start_arity, self.schema.total_arity, self.schema.level
            )
        }
    }

    fn get_degree_from_pinning(&self, path: impl AsRef<Path>) -> u32 {
        let col_degree = |agg: bool| match agg {
            false => EthConfigPinning::from_path(path.as_ref()).degree(),
            true => AggregationConfigPinning::from_path(path.as_ref()).degree(),
        };
        match self.initial_type {
            InitialCircuitType::Account => col_degree(self.aggregate),
            InitialCircuitType::Storage => col_degree(self.aggregate),
            InitialCircuitType::RowConsistency => {
                AggregationConfigPinning::from_path(path).degree()
            }
        }
    }
}

/// Schema to aggregate the proof of 2<sup>arities.sum()</sup> rows.
///
/// * `arities`: At level `i` we prove 2<sup>arities\[i\]</sup> entries if i = 0 or aggregate 2<sup>arities\[i\]</sup> previous proofs.
/// Here level is “reverse” from depth, so the root has the highest level, while leaf is level 0.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVerifyVsMmrCircuitType {
    pub network: Network,
    pub arities: Vec<usize>,
}

impl scheduler::CircuitType for BlockVerifyVsMmrCircuitType {
    fn name(&self) -> String {
        format!("{}_block_{}", self.network, self.arities.iter().join("_"))
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        if self.arities.len() == 1 {
            EthConfigPinning::from_path(pinning_path.as_ref()).degree()
        } else {
            AggregationConfigPinning::from_path(pinning_path.as_ref()).degree()
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalAssemblyCircuitType {
    /// Performs `round` rounds of SNARK verification using `PublicAggregationCircuit` on the final circuit.
    /// This is used to reduce circuit size and final EVM verification gas costs.
    pub round: usize,
    pub network: Network,
    pub block_arities: Vec<usize>,
    pub account_schema: ExponentialSchema,
    pub storage_schema: ExponentialSchema,
    pub row_schema: ExponentialSchema,
}

impl FinalAssemblyCircuitType {
    pub fn new(
        round: usize,
        network: Network,
        block_arities: Vec<usize>,
        account_schema: ExponentialSchema,
        storage_schema: ExponentialSchema,
        row_schema: ExponentialSchema,
    ) -> Self {
        let block_arity = block_arities.iter().sum::<usize>();
        assert_eq!(block_arity, account_schema.total_arity);
        assert_eq!(block_arity, storage_schema.total_arity);
        assert_eq!(block_arity, row_schema.total_arity);
        Self { round, network, block_arities, account_schema, storage_schema, row_schema }
    }
}

impl scheduler::CircuitType for FinalAssemblyCircuitType {
    fn name(&self) -> String {
        format!("final_{}", self.round)
    }

    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        if self.round == 0 {
            EthConfigPinning::from_path(pinning_path.as_ref()).degree()
        } else {
            AggregationConfigPinning::from_path(pinning_path.as_ref()).degree()
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitType {
    /// Circuit to either create a response column or check consistency of the response table
    Response(ResponseCircuitType),
    /// Circuit to verify block responses against block hash MMR
    VerifyVsMmr(BlockVerifyVsMmrCircuitType),
    /// Circuit to aggregate all response columns into a single response table and verify consistency.
    Final(FinalAssemblyCircuitType),
}

impl scheduler::CircuitType for CircuitType {
    fn name(&self) -> String {
        match self {
            CircuitType::Response(circuit_type) => circuit_type.name(),
            CircuitType::VerifyVsMmr(circuit_type) => circuit_type.name(),
            CircuitType::Final(circuit_type) => circuit_type.name(),
        }
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        match self {
            CircuitType::Response(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }
            CircuitType::VerifyVsMmr(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }
            CircuitType::Final(circuit_type) => circuit_type.get_degree_from_pinning(pinning_path),
        }
    }
}

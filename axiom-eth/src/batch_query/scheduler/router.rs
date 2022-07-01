use std::path::Path;

use any_circuit_derive::AnyCircuit;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use itertools::Itertools;
use snark_verifier_sdk::Snark;

use crate::{
    batch_query::{
        aggregation::{
            FinalResponseAssemblyCircuit, HashStrategy, MultiBlockAggregationCircuit,
            PoseidonAggregationCircuit,
        },
        response::{
            account::MultiAccountCircuit,
            block_header::MultiBlockCircuit,
            row_consistency::{RowConsistencyCircuit, ROW_CIRCUIT_NUM_INSTANCES},
            storage::MultiStorageCircuit,
        },
    },
    util::{
        circuit::{AnyCircuit, PublicAggregationCircuit},
        scheduler::{self, EthScheduler},
    },
};

use super::tasks::{ResponseInput, Task};

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, AnyCircuit)]
pub enum CircuitRouter {
    // response circuits
    InitialAccount(MultiAccountCircuit),
    InitialStorage(MultiStorageCircuit),
    RowConsistency(RowConsistencyCircuit),
    BlockVerifyVsMmr(MultiBlockCircuit),
    // aggregation circuits
    FinalAssembly(FinalResponseAssemblyCircuit),
    Passthrough(PublicAggregationCircuit),
    Poseidon(PoseidonAggregationCircuit),
    BlockVerifyMmrAggregation(MultiBlockAggregationCircuit),
}

pub type BatchQueryScheduler = EthScheduler<Task>;

impl scheduler::Scheduler for BatchQueryScheduler {
    type Task = Task;
    type CircuitRouter = CircuitRouter;

    fn get_circuit(&self, task: Task, prev_snarks: Vec<Snark>) -> CircuitRouter {
        match task {
            Task::Final(final_task) => {
                if final_task.circuit_type.round != 0 {
                    assert_eq!(prev_snarks.len(), 1);
                    return CircuitRouter::Passthrough(PublicAggregationCircuit::new(
                        prev_snarks.into_iter().map(|snark| (snark, true)).collect(),
                    ));
                }
                let circuit_type = &final_task.circuit_type;
                let block_has_acc = circuit_type.block_arities.len() != 1;
                let [account_has_acc, storage_has_acc, row_has_acc] = [
                    &circuit_type.account_schema,
                    &circuit_type.storage_schema,
                    &circuit_type.row_schema,
                ]
                .map(|schema| schema.start_arity != schema.total_arity);
                let [block_snark, account_snark, storage_snark, row_snark]: [_; 4] =
                    prev_snarks.try_into().unwrap();
                CircuitRouter::FinalAssembly(FinalResponseAssemblyCircuit::new(
                    (block_snark, block_has_acc),
                    (account_snark, account_has_acc),
                    (storage_snark, storage_has_acc),
                    (row_snark, row_has_acc),
                ))
            }
            Task::Response(task) => {
                if task.aggregate {
                    let acc = (task.schema.level + 1)
                        != (task.schema.total_arity - task.schema.start_arity);
                    let prev_snarks = prev_snarks
                        .into_iter()
                        .zip_eq([false, acc])
                        .map(|(snark, has_acc)| (snark, has_acc))
                        .collect_vec();
                    if !matches!(&task.input, ResponseInput::Row(_)) || task.schema.level != 0 {
                        CircuitRouter::Passthrough(PublicAggregationCircuit::new(prev_snarks))
                    } else {
                        // final aggregation of row consistency should do poseidon hash onion
                        CircuitRouter::Poseidon(PoseidonAggregationCircuit::new(
                            HashStrategy::Onion,
                            prev_snarks,
                            ROW_CIRCUIT_NUM_INSTANCES, // all poseidon roots
                        ))
                    }
                } else {
                    match task.input {
                        ResponseInput::Account(input) => CircuitRouter::InitialAccount(input),
                        ResponseInput::Storage(input) => CircuitRouter::InitialStorage(input),
                        ResponseInput::Row(input) => CircuitRouter::RowConsistency(input),
                    }
                }
            }
            Task::BlockVerifyVsMmr(task) => {
                if task.arities.len() == 1 {
                    CircuitRouter::BlockVerifyVsMmr(task.input)
                } else {
                    let has_acc = task.arities.len() > 2;
                    CircuitRouter::BlockVerifyMmrAggregation(MultiBlockAggregationCircuit {
                        snarks: prev_snarks.into_iter().map(|snark| (snark, has_acc)).collect(),
                    })
                }
            }
        }
    }
}

use ethers_core::{
    types::{Address, H256},
    utils::keccak256,
};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use snark_verifier::util::hash::Poseidon;
use snark_verifier_sdk::{halo2::POSEIDON_SPEC, NativeLoader};

use crate::{
    batch_query::response::{
        account::MultiAccountCircuit,
        block_header::{MultiBlockCircuit, GENESIS_BLOCK_RLP},
        native::{get_account_response, get_block_response, FullStorageResponse},
        row_consistency::RowConsistencyCircuit,
        storage::{MultiStorageCircuit, DEFAULT_STORAGE_QUERY},
    },
    storage::{EthBlockStorageInput, EthStorageInput},
    util::scheduler,
};

use super::circuit_types::{
    BlockVerifyVsMmrCircuitType, CircuitType, ExponentialSchema, FinalAssemblyCircuitType,
    InitialCircuitType, ResponseCircuitType,
};

/// The input queries for {block, account, storage} column task.
///
/// The lengths of the queries do not need to be a power of two, because we will
/// pad it with "default" entries to optimize caching.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ResponseInput {
    Account(MultiAccountCircuit),
    Storage(MultiStorageCircuit),
    Row(RowConsistencyCircuit),
}

impl ResponseInput {
    fn initial_type(&self) -> InitialCircuitType {
        match self {
            ResponseInput::Account(_) => InitialCircuitType::Account,
            ResponseInput::Storage(_) => InitialCircuitType::Storage,
            ResponseInput::Row(_) => InitialCircuitType::RowConsistency,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseTask {
    pub input: ResponseInput,
    pub schema: ExponentialSchema,
    pub aggregate: bool,
}

impl scheduler::Task for ResponseTask {
    type CircuitType = ResponseCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        ResponseCircuitType {
            initial_type: self.input.initial_type(),
            schema: self.schema.clone(),
            aggregate: self.aggregate,
        }
    }

    /// This needs to be collision-resistant because we are using file system for caching right now.
    // Not the most efficient, but we're just going to serialize the whole task and keccak it
    fn name(&self) -> String {
        let hash = match &self.input {
            ResponseInput::Row(_) => {
                // something about `Block` makes this hard to serialize with bincode
                keccak256(serde_json::to_vec(&self).expect("failed to serialize task"))
            }
            _ => keccak256(bincode::serialize(&self).expect("failed to serialize task")),
        };
        format!("{:?}", H256(hash))
    }

    fn dependencies(&self) -> Vec<Self> {
        if !self.aggregate || self.schema.level == self.schema.total_arity - self.schema.start_arity
        {
            return vec![];
        }
        let arity = self.schema.level_arity();
        let mid = 1 << arity;
        let prev_inputs = match &self.input {
            ResponseInput::Account(input) => {
                let (block_responses1, block_responses2) = input.block_responses.split_at(mid);
                let (queries1, queries2) = input.queries.split_at(mid);
                let (not_empty1, not_empty2) = input.not_empty.split_at(mid);
                [block_responses1, block_responses2]
                    .zip([queries1, queries2])
                    .zip([not_empty1, not_empty2])
                    .map(|((block_responses, queries), not_empty)| MultiAccountCircuit {
                        block_responses: block_responses.to_vec(),
                        queries: queries.to_vec(),
                        not_empty: not_empty.to_vec(),
                    })
                    .map(ResponseInput::Account)
            }
            ResponseInput::Storage(input) => {
                let (block_responses1, block_responses2) = input.block_responses.split_at(mid);
                let (account_responses1, account_responses2) =
                    input.account_responses.split_at(mid);
                let (queries1, queries2) = input.queries.split_at(mid);
                let (not_empty1, not_empty2) = input.not_empty.split_at(mid);
                [block_responses1, block_responses2]
                    .zip([account_responses1, account_responses2])
                    .zip([queries1, queries2])
                    .zip([not_empty1, not_empty2])
                    .map(|(((block_responses, account_responses), queries), not_empty)| {
                        MultiStorageCircuit {
                            block_responses: block_responses.to_vec(),
                            account_responses: account_responses.to_vec(),
                            queries: queries.to_vec(),
                            not_empty: not_empty.to_vec(),
                        }
                    })
                    .map(ResponseInput::Storage)
            }
            ResponseInput::Row(input) => {
                let (responses1, responses2) = input.responses.split_at(mid);
                let (block_not_empty1, block_not_empty2) = input.block_not_empty.split_at(mid);
                let (account_not_empty1, account_not_empty2) =
                    input.account_not_empty.split_at(mid);
                let (storage_not_empty1, storage_not_empty2) =
                    input.storage_not_empty.split_at(mid);
                [responses1, responses2]
                    .zip([block_not_empty1, block_not_empty2])
                    .zip([account_not_empty1, account_not_empty2])
                    .zip([storage_not_empty1, storage_not_empty2])
                    .map(
                        |(((responses, block_not_empty), account_not_empty), storage_not_empty)| {
                            RowConsistencyCircuit {
                                responses: responses.to_vec(),
                                block_not_empty: block_not_empty.to_vec(),
                                account_not_empty: account_not_empty.to_vec(),
                                storage_not_empty: storage_not_empty.to_vec(),
                                network: input.network,
                            }
                        },
                    )
                    .map(ResponseInput::Row)
            }
        };
        let next_schema = self.schema.next();
        let agg = self.schema.level != (self.schema.total_arity - self.schema.start_arity - 1);
        prev_inputs
            .into_iter()
            .zip([self.schema.clone(), next_schema])
            .zip([false, agg])
            .map(|((input, schema), aggregate)| Self { input, schema, aggregate })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockVerifyVsMmrTask {
    pub input: MultiBlockCircuit,
    pub arities: Vec<usize>,
}

impl scheduler::Task for BlockVerifyVsMmrTask {
    type CircuitType = BlockVerifyVsMmrCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        BlockVerifyVsMmrCircuitType { network: self.input.network, arities: self.arities.clone() }
    }

    fn name(&self) -> String {
        format!(
            "{:?}",
            H256(keccak256(bincode::serialize(&self).expect("failed to serialize task")))
        )
    }

    fn dependencies(&self) -> Vec<Self> {
        assert!(!self.arities.is_empty());
        if self.arities.len() == 1 {
            return vec![];
        }
        let arity = self.arities.last().unwrap();
        let prev_arities = self.arities[..self.arities.len() - 1].to_vec();
        let prev_arity = prev_arities.iter().sum::<usize>();
        let chunk_size = 1 << prev_arity;
        let num_chunks = 1 << arity;

        let mut prev_inputs = self
            .input
            .header_rlp_encodings
            .chunks(chunk_size)
            .zip_eq(self.input.not_empty.chunks(chunk_size))
            .zip_eq(self.input.mmr_proofs.chunks(chunk_size))
            .map(|((header_rlps, not_empty), mmr_proofs)| {
                MultiBlockCircuit::resize_from(
                    header_rlps.to_vec(),
                    not_empty.to_vec(),
                    self.input.network,
                    self.input.mmr.to_vec(),
                    self.input.mmr_list_len,
                    mmr_proofs.iter().map(|pf| pf.to_vec()).collect(),
                    chunk_size,
                )
            })
            .collect_vec();
        let dup = prev_inputs[0].clone();
        prev_inputs.resize(num_chunks, dup);

        prev_inputs.into_iter().map(|input| Self { input, arities: prev_arities.clone() }).collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalAssemblyTask {
    pub circuit_type: FinalAssemblyCircuitType,
    pub input: Vec<FullStorageResponse>,
    pub mmr: Vec<H256>,
    pub mmr_num_blocks: usize,
    pub mmr_proofs: Vec<Vec<H256>>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Task {
    Response(ResponseTask),
    BlockVerifyVsMmr(BlockVerifyVsMmrTask),
    Final(FinalAssemblyTask),
}

impl scheduler::Task for Task {
    type CircuitType = CircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        match self {
            Task::Response(task) => CircuitType::Response(task.circuit_type()),
            Task::BlockVerifyVsMmr(task) => CircuitType::VerifyVsMmr(task.circuit_type()),
            Task::Final(task) => CircuitType::Final(task.circuit_type.clone()),
        }
    }

    fn name(&self) -> String {
        match self {
            Task::Response(task) => task.name(),
            Task::BlockVerifyVsMmr(task) => task.name(),
            Task::Final(task) => {
                format!(
                    "final_{:?}",
                    H256(keccak256(serde_json::to_vec(&task).expect("failed to serialize task")))
                )
            }
        }
    }

    fn dependencies(&self) -> Vec<Self> {
        match self {
            Task::Response(task) => task.dependencies().into_iter().map(Task::Response).collect(),
            Task::BlockVerifyVsMmr(task) => {
                task.dependencies().into_iter().map(Task::BlockVerifyVsMmr).collect()
            }
            Task::Final(task) => {
                if task.circuit_type.round != 0 {
                    let mut circuit_type = task.circuit_type.clone();
                    circuit_type.round -= 1;
                    return vec![Task::Final(FinalAssemblyTask { circuit_type, ..task.clone() })];
                }
                let circuit_type = &task.circuit_type;

                let total_arity: usize = circuit_type.block_arities.iter().sum::<usize>();
                assert_eq!(total_arity, circuit_type.account_schema.total_arity);
                assert_eq!(total_arity, circuit_type.storage_schema.total_arity);
                assert_eq!(total_arity, circuit_type.row_schema.total_arity);
                let mut account_schema = circuit_type.account_schema.clone();
                let mut storage_schema = circuit_type.storage_schema.clone();
                let mut row_schema = circuit_type.row_schema.clone();
                account_schema.level = 0;
                storage_schema.level = 0;
                row_schema.level = 0;

                let network = circuit_type.network;
                let len = 1 << total_arity;
                let mut block_header_rlps = Vec::with_capacity(len);
                let mut block_headers_poseidon = Vec::with_capacity(len);
                let mut block_responses = Vec::with_capacity(len);
                let mut account_responses = Vec::with_capacity(len);
                let mut storage_inputs = Vec::with_capacity(len);
                let mut block_not_empty = Vec::with_capacity(len);
                let mut account_not_empty = Vec::with_capacity(len);
                let mut storage_not_empty = Vec::with_capacity(len);
                let mut responses = Vec::with_capacity(len);

                let mut poseidon = Poseidon::from_spec(&NativeLoader, POSEIDON_SPEC.clone());
                let hasher = &mut poseidon;

                for input in &task.input {
                    let mut response = EthBlockStorageInput::from(input.clone());
                    block_header_rlps.push(response.block_header.clone());
                    let ((block_res_p, _block_res_k), block_res) =
                        get_block_response(hasher, input.block.clone(), network);
                    block_responses.push((block_res_p, input.block.number.unwrap().as_u32()));
                    block_not_empty.push(true);
                    block_headers_poseidon.push(block_res.header_poseidon);

                    if let Some(acct_storage) = &input.account_storage {
                        let ((acct_res_p, _acct_res_k), _) =
                            get_account_response(hasher, acct_storage);
                        account_responses.push((acct_res_p, acct_storage.addr));
                        account_not_empty.push(true);
                        if !acct_storage.storage_pfs.is_empty() {
                            assert!(acct_storage.storage_pfs.len() == 1);
                            storage_inputs.push(acct_storage.clone());
                            storage_not_empty.push(true);
                        } else {
                            response.storage.storage_pfs =
                                DEFAULT_STORAGE_QUERY.storage_pfs.clone();
                            storage_inputs.push(response.storage.clone());
                            storage_not_empty.push(false);
                        }
                    } else {
                        account_responses.push((Fr::zero(), Address::zero()));
                        account_not_empty.push(false);
                        storage_inputs.push(DEFAULT_STORAGE_QUERY.clone());
                        storage_not_empty.push(false);
                    }
                    responses.push(response);
                }
                let mut input_arity = block_header_rlps.len().ilog2() as usize;
                if (1 << input_arity) != block_header_rlps.len() {
                    input_arity += 1;
                }
                block_header_rlps.resize_with(1 << input_arity, || GENESIS_BLOCK_RLP.to_vec());
                block_not_empty.resize(1 << input_arity, false);
                let mut mmr_proofs = task.mmr_proofs.clone();
                mmr_proofs.resize(1 << input_arity, vec![]);

                let num_chunks = 1 << (total_arity - input_arity);

                let block_header_rlps =
                    (0..num_chunks).flat_map(|_| block_header_rlps.clone()).collect_vec();
                let block_not_empty =
                    (0..num_chunks).flat_map(|_| block_not_empty.clone()).collect_vec();
                let mmr_proofs = (0..num_chunks).flat_map(|_| mmr_proofs.clone()).collect_vec();

                let block_task = MultiBlockCircuit::new(
                    block_header_rlps,
                    block_not_empty.clone(),
                    network,
                    task.mmr.clone(),
                    task.mmr_num_blocks,
                    mmr_proofs,
                );
                let acct_inputs = storage_inputs
                    .iter()
                    .map(|input| EthStorageInput { storage_pfs: vec![], ..input.clone() })
                    .collect_vec();
                let acct_task = MultiAccountCircuit::resize_from(
                    block_responses
                        .iter()
                        .zip(account_not_empty.iter())
                        .map(|(res, &ne)| if ne { *res } else { (Fr::zero(), 0) })
                        .collect_vec(),
                    acct_inputs,
                    account_not_empty.clone(),
                    len,
                );
                let storage_task = MultiStorageCircuit::resize_from(
                    block_responses
                        .iter()
                        .zip(storage_not_empty.iter())
                        .map(|(res, &ne)| if ne { *res } else { (Fr::zero(), 0) })
                        .collect_vec(),
                    account_responses
                        .iter()
                        .zip(storage_not_empty.iter())
                        .map(|(res, &ne)| if ne { *res } else { (Fr::zero(), Address::zero()) })
                        .collect_vec(),
                    storage_inputs,
                    storage_not_empty.clone(),
                    len,
                );
                let row_consistency_task = RowConsistencyCircuit::resize_from(
                    responses,
                    block_not_empty,
                    account_not_empty,
                    storage_not_empty,
                    network,
                    len,
                );

                vec![
                    Task::BlockVerifyVsMmr(BlockVerifyVsMmrTask {
                        input: block_task,
                        arities: circuit_type.block_arities.clone(),
                    }),
                    Task::Response(ResponseTask {
                        aggregate: account_schema.start_arity != account_schema.total_arity,
                        schema: account_schema,
                        input: ResponseInput::Account(acct_task),
                    }),
                    Task::Response(ResponseTask {
                        aggregate: storage_schema.start_arity != storage_schema.total_arity,
                        schema: storage_schema,
                        input: ResponseInput::Storage(storage_task),
                    }),
                    Task::Response(ResponseTask {
                        aggregate: row_schema.start_arity != row_schema.total_arity,
                        schema: row_schema,
                        input: ResponseInput::Row(row_consistency_task),
                    }),
                ]
            }
        }
    }
}

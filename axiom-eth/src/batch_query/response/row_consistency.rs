//! Checks consistency of `BlockResponse`, `AccountResponse` and `StorageResponse`
//! by decommiting hash and going row-by-row.
use std::env::var;
use std::str::FromStr;

use ethers_core::types::H256;
use halo2_base::gates::builder::{
    CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
    RangeWithInstanceCircuitBuilder,
};
use halo2_base::halo2_proofs::halo2curves::bn256::G1Affine;
use itertools::Itertools;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use snark_verifier::{loader::ScalarLoader, util::hash::Poseidon};
use snark_verifier_sdk::{halo2::POSEIDON_SPEC, NativeLoader};

use super::storage::DEFAULT_STORAGE_QUERY;
use super::{native::get_block_response, *};
use crate::batch_query::hash::poseidon_tree_root;
use crate::batch_query::response::block_header::{GENESIS_BLOCK, GENESIS_BLOCK_RLP};
use crate::batch_query::response::native::NativeBlockResponse;
use crate::batch_query::DummyEccChip;
use crate::Field;
use crate::{
    batch_query::{
        hash::{create_merkle_proof, poseidon_packed, traverse_merkle_proof},
        response::{
            account::STORAGE_ROOT_INDEX,
            native::{
                get_account_response, get_storage_response, NativeAccountResponse,
                NativeStorageResponse,
            },
        },
    },
    block_header::{BLOCK_NUMBER_INDEX, STATE_ROOT_INDEX},
    rlp::rlc::FIRST_PHASE,
    storage::EthBlockStorageInput,
    util::load_bool,
    Network,
};

/// The input data for a circuit that checks consistency of columns for `BlockResponse`, `AccountResponse` and `StorageResponse`.
///
/// Assumptions:
/// * `responses`, `block_not_empty`, `account_not_empty` and `storage_not_empty` to all be the same length, and length is a power of two.
///
/// Public instances consist of [`ROW_CIRCUIT_NUM_INSTANCES`] field elements:
/// * `poseidon_tree_root(block_responses.poseidon)`
/// * `poseidon_tree_root(block_responses.keccak)`
/// * `poseidon_tree_root(full_account_responses.poseidon)`
/// * `poseidon_tree_root([account_not_empty[i] ? block_number[i] : 0x0 for all i])`
/// * `poseidon_tree_root(account_responses.keccak)`
/// * `poseidon_tree_root(full_storage_responses.poseidon)`
/// * `poseidon_tree_root([storage_not_empty[i] ? block_number[i] : 0x0 for all i])`
/// * `poseidon_tree_root([storage_not_empty[i] ? address[i] : 0x0 for all i])`
///
/// Since a Poseidon hash is `0` with vanishingly small probability, the Poseidon Merkle roots above commit to the data of whether a column entry is empty or not.
/// `block_responses[i]` is zero if `block_not_empty[i]` is false, and similarly for `full_account_responses[i]` and `full_storage_responses[i]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RowConsistencyCircuit {
    pub responses: Vec<EthBlockStorageInput>,
    pub block_not_empty: Vec<bool>,
    pub account_not_empty: Vec<bool>,
    pub storage_not_empty: Vec<bool>,
    pub network: Network,
}

pub(crate) const ROW_CIRCUIT_NUM_INSTANCES: usize = 6;
pub(crate) const ROW_BLOCK_POSEIDON_INDEX: usize = 0;
pub(crate) const ROW_ACCT_POSEIDON_INDEX: usize = 1;
pub(crate) const ROW_ACCT_BLOCK_KECCAK_INDEX: usize = 2;
pub(crate) const ROW_STORAGE_POSEIDON_INDEX: usize = 3;
pub(crate) const ROW_STORAGE_BLOCK_KECCAK_INDEX: usize = 4;
pub(crate) const ROW_STORAGE_ACCT_KECCAK_INDEX: usize = 5;

impl RowConsistencyCircuit {
    pub fn new(
        responses: Vec<EthBlockStorageInput>,
        block_not_empty: Vec<bool>,
        account_not_empty: Vec<bool>,
        storage_not_empty: Vec<bool>,
        network: Network,
    ) -> Self {
        assert!(responses.len().is_power_of_two());
        assert_eq!(responses.len(), account_not_empty.len());
        assert_eq!(account_not_empty.len(), storage_not_empty.len());
        for ((&block_not_empty, &account_not_empty), &storage_not_empty) in
            block_not_empty.iter().zip_eq(account_not_empty.iter()).zip_eq(storage_not_empty.iter())
        {
            assert_eq!(account_not_empty, account_not_empty && block_not_empty);
            assert_eq!(storage_not_empty, storage_not_empty && account_not_empty);
        }
        Self { responses, block_not_empty, account_not_empty, storage_not_empty, network }
    }

    pub fn resize_from(
        mut responses: Vec<EthBlockStorageInput>,
        mut block_not_empty: Vec<bool>,
        mut account_not_empty: Vec<bool>,
        mut storage_not_empty: Vec<bool>,
        network: Network,
        new_len: usize,
    ) -> Self {
        responses.resize_with(new_len, || DEFAULT_ROW_CONSISTENCY_INPUT.clone());
        block_not_empty.resize(new_len, false);
        account_not_empty.resize(new_len, false);
        storage_not_empty.resize(new_len, false);
        Self::new(responses, block_not_empty, account_not_empty, storage_not_empty, network)
    }

    pub fn verify<C, EccChip, const T: usize, const RATE: usize>(
        self,
        loader: &Rc<Halo2Loader<C, EccChip>>,
        hasher: &mut Poseidon<C::Scalar, Scalar<C, EccChip>, T, RATE>,
        native_hasher: &mut Poseidon<C::Scalar, C::Scalar, T, RATE>,
    ) -> Vec<AssignedValue<C::Scalar>>
    where
        C: CurveAffine,
        C::Scalar: Field,
        EccChip: EccInstructions<C::Scalar, C>,
    {
        let mut row_data =
            [(); ROW_CIRCUIT_NUM_INSTANCES].map(|_| Vec::with_capacity(self.responses.len()));

        let mut tmp_builder = loader.ctx_mut();
        let ctx = tmp_builder.main(FIRST_PHASE);
        let gate: &GateChip<C::Scalar> = &loader.scalar_chip();
        let ((block_not_empty, account_not_empty), storage_not_empty): ((Vec<_>, Vec<_>), Vec<_>) =
            self.block_not_empty
                .into_iter()
                .zip_eq(self.account_not_empty.into_iter())
                .zip_eq(self.storage_not_empty.into_iter())
                .map(|((block_not_empty, account_not_empty), storage_not_empty)| {
                    let [block_not_empty, account_not_empty, storage_not_empty] =
                        [block_not_empty, account_not_empty, storage_not_empty]
                            .map(|x| load_bool(ctx, gate, x));
                    let account_not_empty = gate.mul(ctx, block_not_empty, account_not_empty);
                    // storage can only be empty if account is empty
                    let storage_not_empty = gate.mul(ctx, account_not_empty, storage_not_empty);
                    ((block_not_empty, account_not_empty), storage_not_empty)
                })
                .unzip();
        drop(tmp_builder);

        for (((full_response, block_not_empty), account_not_empty), storage_not_empty) in self
            .responses
            .into_iter()
            .zip(block_not_empty)
            .zip(account_not_empty)
            .zip(storage_not_empty)
        {
            // ==================
            // load poseidon hashes of responses as private witnesses and merkle proof into relevant fields
            // ==================
            // generate block header natively
            let (
                (_block_res_p, _block_res_k),
                NativeBlockResponse { block_hash, header_list, header_poseidon: _ },
            ) = get_block_response(native_hasher, full_response.block, self.network);
            // merkle proof state root all the way into block_response_poseidon
            // load witnesses (loader)
            let [state_root, block_hash, block_number] =
                [&header_list[STATE_ROOT_INDEX], &block_hash, &header_list[BLOCK_NUMBER_INDEX]]
                    .map(|x| PoseidonWords::from_witness(loader, x));
            // create merkle proof for state root
            let merkle_proof = create_merkle_proof(native_hasher, header_list, STATE_ROOT_INDEX);
            let merkle_proof = merkle_proof
                .into_iter()
                .map(|w| PoseidonWords::from_witness(loader, w.0))
                .collect_vec();
            // use proof to compute root
            let header_poseidon =
                traverse_merkle_proof(hasher, &merkle_proof, state_root.clone(), STATE_ROOT_INDEX);
            let mut block_response_poseidon =
                poseidon_packed(hasher, block_hash.concat(&block_number).concat(&header_poseidon));
            debug_assert_eq!(block_response_poseidon.assigned().value(), &_block_res_p);
            block_response_poseidon *= loader.scalar_from_assigned(block_not_empty);
            row_data[ROW_BLOCK_POSEIDON_INDEX]
                .push(PoseidonWords::from(block_response_poseidon.clone()));

            // generate account response natively
            let (
                (_account_res_p, _),
                NativeAccountResponse { state_root: _state_root, state_list, address },
            ) = get_account_response(native_hasher, &full_response.storage);
            let [storage_root, _state_root, address] =
                [&state_list[STORAGE_ROOT_INDEX], &_state_root, &address]
                    .map(|x| PoseidonWords::from_witness(loader, x));
            // create merkle proof for storage root
            let merkle_proof = create_merkle_proof(native_hasher, state_list, STORAGE_ROOT_INDEX);
            let merkle_proof = merkle_proof
                .into_iter()
                .map(|w| PoseidonWords::from_witness(loader, w.0))
                .collect_vec();
            let state_poseidon = traverse_merkle_proof(
                hasher,
                &merkle_proof,
                storage_root.clone(),
                STORAGE_ROOT_INDEX,
            );
            let account_response_poseidon =
                poseidon_packed(hasher, _state_root.concat(&address).concat(&state_poseidon));
            debug_assert_eq!(account_response_poseidon.assigned().value(), &_account_res_p);
            let mut full_acct_res_p = poseidon_packed(
                hasher,
                PoseidonWords(vec![
                    block_response_poseidon.clone(),
                    account_response_poseidon.clone(),
                ]),
            );

            // generate storage response natively
            let (_, NativeStorageResponse { storage_root: _, slot, value }) =
                get_storage_response(native_hasher, &full_response.storage);
            let [slot, value] = [&slot, &value].map(|x| PoseidonWords::from_witness(loader, x));
            let storage_response_poseidon =
                poseidon_packed(hasher, storage_root.concat(&slot).concat(&value));
            let mut full_storage_res_p = poseidon_packed(
                hasher,
                PoseidonWords(vec![
                    block_response_poseidon,
                    account_response_poseidon,
                    storage_response_poseidon,
                ]),
            );

            // ==================
            // check row consistency
            // ==================
            let [account_not_empty, storage_not_empty] =
                [account_not_empty, storage_not_empty].map(|x| loader.scalar_from_assigned(x));
            // state_root from block response must equal _state_root from account response unless account is empty
            // both roots are H256 in hi-lo form; we do not range check these since they are Poseidon committed to
            for (lhs, rhs) in state_root.0.into_iter().zip_eq(_state_root.0.into_iter()) {
                loader.assert_eq(
                    "state root consistency",
                    &(lhs * &account_not_empty),
                    &(rhs * &account_not_empty),
                );
            }
            // we do not need to enforce storage_root since it was direclty used in computation of storage response above

            // in theory the block_response.keccak in the account response could be anything if the account is empty, but for simplicity we enforce that it should be H256::zero()
            let [acct_block_res_k, st_block_res_k] =
                [&account_not_empty, &storage_not_empty].map(|not_empty| {
                    PoseidonWords(block_number.0.iter().map(|x| x.clone() * not_empty).collect())
                });
            // in theory the account_response.keccak in the storage response could be anything if the storage is empty, but for simplicity we enforce that it should be H256::zero()
            let st_acct_res_k =
                PoseidonWords(address.0.iter().map(|x| x.clone() * &storage_not_empty).collect());
            // full account response (poseidon) should be 0 if account is empty
            full_acct_res_p *= account_not_empty;
            // full storage response (poseidon) should be 0 if storage is empty
            full_storage_res_p *= storage_not_empty;

            row_data[ROW_ACCT_POSEIDON_INDEX].push(full_acct_res_p.into());
            row_data[ROW_ACCT_BLOCK_KECCAK_INDEX].push(acct_block_res_k);
            row_data[ROW_STORAGE_POSEIDON_INDEX].push(full_storage_res_p.into());
            row_data[ROW_STORAGE_BLOCK_KECCAK_INDEX].push(st_block_res_k);
            row_data[ROW_STORAGE_ACCT_KECCAK_INDEX].push(st_acct_res_k);
        }
        row_data
            .into_iter()
            .map(|leaves| poseidon_tree_root(hasher, leaves, &[]).into_assigned())
            .collect()
    }
}

impl RowConsistencyCircuit {
    fn create(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
    ) -> RangeWithInstanceCircuitBuilder<Fr> {
        let builder = GateThreadBuilder::new(stage == CircuitBuilderStage::Prover);

        let gate = GateChip::default();
        let loader = Halo2Loader::new(DummyEccChip::<G1Affine>(&gate), builder);
        let mut poseidon = Poseidon::from_spec(&loader, POSEIDON_SPEC.clone());
        let mut native_poseidon = Poseidon::from_spec(&NativeLoader, POSEIDON_SPEC.clone());

        let assigned_instances = self.verify(&loader, &mut poseidon, &mut native_poseidon);
        let builder = loader.take_ctx();
        RangeWithInstanceCircuitBuilder::new(
            match stage {
                CircuitBuilderStage::Mock => RangeCircuitBuilder::mock(builder),
                CircuitBuilderStage::Keygen => RangeCircuitBuilder::keygen(builder),
                CircuitBuilderStage::Prover => {
                    RangeCircuitBuilder::prover(builder, break_points.unwrap())
                }
            },
            assigned_instances,
        )
    }

    pub fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        k: u32,
    ) -> RangeWithInstanceCircuitBuilder<Fr> {
        let circuit = self.create(stage, break_points);

        #[cfg(not(feature = "production"))]
        if stage != CircuitBuilderStage::Prover {
            let minimum_rows = var("UNUSABLE_ROWS").map(|s| s.parse().unwrap_or(10)).unwrap_or(10);
            circuit.config(k, Some(minimum_rows));
        }
        circuit
    }
}

lazy_static! {
    /// Default row. NOTE: block and storage are NOT consistent. Assumed that account and storage should be marked "empty".
    pub static ref DEFAULT_ROW_CONSISTENCY_INPUT: EthBlockStorageInput = EthBlockStorageInput {
        block: GENESIS_BLOCK.clone(),
        block_hash: H256::from_str(
            "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
        )
        .unwrap(),
        block_header: GENESIS_BLOCK_RLP.to_vec(),
        block_number: 0u32,
        storage: DEFAULT_STORAGE_QUERY.clone(),
    };
}

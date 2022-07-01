/// The native implementation of the {Poseidon, Keccak} response of queries.
use crate::{
    batch_query::hash::{poseidon_packed, poseidon_tree_root, PoseidonWords},
    block_header::{
        EXTRA_DATA_INDEX, GOERLI_EXTRA_DATA_MAX_BYTES, MAINNET_EXTRA_DATA_MAX_BYTES,
        MAINNET_HEADER_FIELDS_MAX_BYTES, NUM_BLOCK_HEADER_FIELDS,
    },
    providers::get_block_rlp,
    storage::{EthBlockStorageInput, EthStorageInput},
    Network,
};
use ethers_core::{
    types::{Address, Block, H256},
    utils::keccak256,
};
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use snark_verifier::util::hash::Poseidon;

use super::storage::DEFAULT_STORAGE_QUERY;

#[derive(Clone, Debug)]
pub(crate) struct NativeBlockResponse<F: FieldExt> {
    pub block_hash: PoseidonWords<F>,
    pub header_list: Vec<PoseidonWords<F>>,
    pub header_poseidon: F,
}

/// Computes
/// ```
/// block_response = hash(blockHash . blockNumber . hash_tree_root(blockHeader))
/// ```
/// where `hash` is {Poseidon, Keccak}
///
/// Also returns block header as list of PoseidonWords.
pub(crate) fn get_block_response<F: FieldExt, const T: usize, const RATE: usize>(
    poseidon: &mut Poseidon<F, F, T, RATE>,
    block: Block<H256>,
    network: Network,
) -> ((F, H256), NativeBlockResponse<F>) {
    let mut header_list = Vec::with_capacity(32);
    header_list.push(block.parent_hash.0.to_vec());
    header_list.push(block.uncles_hash.0.to_vec());
    header_list.push(block.author.unwrap().0.to_vec());
    header_list.push(block.state_root.0.to_vec());
    header_list.push(block.transactions_root.0.to_vec());
    header_list.push(block.receipts_root.0.to_vec());
    header_list.push(block.logs_bloom.unwrap().0.to_vec());
    let mut difficulty = [0u8; 32];
    block.difficulty.to_big_endian(&mut difficulty);
    let difficulty = difficulty[32 - MAINNET_HEADER_FIELDS_MAX_BYTES[7]..].to_vec();
    header_list.push(difficulty);
    let mut number = [0u8; 8];
    block.number.unwrap().to_big_endian(&mut number);
    let number = number[8 - MAINNET_HEADER_FIELDS_MAX_BYTES[8]..].to_vec();
    header_list.push(number.clone());
    let mut gas_limit = [0u8; 32];
    block.gas_limit.to_big_endian(&mut gas_limit);
    let gas_limit = gas_limit[32 - MAINNET_HEADER_FIELDS_MAX_BYTES[9]..].to_vec();
    header_list.push(gas_limit);
    let mut gas_used = [0u8; 32];
    block.gas_used.to_big_endian(&mut gas_used);
    let gas_used = gas_used[32 - MAINNET_HEADER_FIELDS_MAX_BYTES[10]..].to_vec();
    header_list.push(gas_used);
    let mut timestamp = [0u8; 32];
    block.timestamp.to_big_endian(&mut timestamp);
    let timestamp = timestamp[32 - MAINNET_HEADER_FIELDS_MAX_BYTES[11]..].to_vec();
    header_list.push(timestamp);
    let extra_data_len = match network {
        Network::Mainnet => MAINNET_EXTRA_DATA_MAX_BYTES,
        Network::Goerli => GOERLI_EXTRA_DATA_MAX_BYTES,
    };
    let mut extra_data = vec![0u8; extra_data_len];
    extra_data[..block.extra_data.len()].copy_from_slice(&block.extra_data);
    header_list.push(extra_data);
    header_list.push(block.mix_hash.unwrap().0.to_vec());
    header_list.push(block.nonce.unwrap().0.to_vec());
    header_list.push(
        block
            .base_fee_per_gas
            .map(|uint| {
                let mut bytes = [0u8; 32];
                uint.to_big_endian(&mut bytes);
                bytes[32 - MAINNET_HEADER_FIELDS_MAX_BYTES[15]..].to_vec()
            })
            .unwrap_or_default(),
    );
    header_list.push(block.withdrawals_root.map(|root| root.0.to_vec()).unwrap_or_default());
    assert_eq!(
        header_list.len(),
        NUM_BLOCK_HEADER_FIELDS,
        "Discrepancy in assumed max number of block header fields. Has there been a hard fork recently?"
    );
    let mut header_list = header_list.iter().map(|x| bytes_to_poseidon_words(x)).collect_vec();
    header_list[EXTRA_DATA_INDEX].0.insert(0, F::from(block.extra_data.len() as u64));
    let mut depth = header_list.len().ilog2();
    if 1 << depth != header_list.len() {
        depth += 1;
    }
    header_list.resize(1 << depth, PoseidonWords(vec![]));
    let header_poseidon = poseidon_tree_root(poseidon, header_list.clone(), &[]);

    let block_hash = block.hash.unwrap();
    let response_keccak = keccak256([block_hash.as_bytes(), &number[..]].concat());
    let block_hash = bytes_to_poseidon_words(block_hash.as_bytes());
    let response_poseidon = poseidon_packed(
        poseidon,
        block_hash.concat(&bytes_to_poseidon_words(&number[..])).concat(&header_poseidon.into()),
    );
    (
        (response_poseidon, response_keccak.into()),
        NativeBlockResponse { block_hash, header_list, header_poseidon },
    )
}

#[derive(Clone, Debug)]
pub(crate) struct NativeAccountResponse<F: FieldExt> {
    pub state_root: PoseidonWords<F>,
    pub address: PoseidonWords<F>,
    pub state_list: Vec<PoseidonWords<F>>,
}

/// Computes
/// ```
/// account_response = hash(stateRoot . address . hash_tree_root(account_state))
/// ```
/// where `hash` is Poseidon
pub(crate) fn get_account_response<F: FieldExt, const T: usize, const RATE: usize>(
    poseidon: &mut Poseidon<F, F, T, RATE>,
    input: &EthStorageInput,
) -> ((F, Vec<u8>), NativeAccountResponse<F>) {
    let state_list = input.acct_state.iter().map(|x| bytes_to_poseidon_words(x)).collect_vec();
    let state_poseidon = poseidon_tree_root(poseidon, state_list.clone(), &[]);
    let state_keccak = keccak256(input.acct_state.concat());
    let response_keccak = [input.addr.as_bytes(), &state_keccak].concat();
    let state_root = bytes_to_poseidon_words(input.acct_pf.root_hash.as_bytes());
    let address = bytes_to_poseidon_words(input.addr.as_bytes());
    let response_poseidon =
        poseidon_packed(poseidon, state_root.concat(&address).concat(&state_poseidon.into()));
    (
        (response_poseidon, response_keccak),
        NativeAccountResponse { state_root, address, state_list },
    )
}

/// Computes
/// ```
/// hash(block_response . account_response)
/// ```
pub fn get_full_account_response<F: FieldExt, const T: usize, const RATE: usize>(
    poseidon: &mut Poseidon<F, F, T, RATE>,
    (block_response, block_number): (F, u32),
    account_response: (F, Vec<u8>),
) -> (F, H256) {
    (
        poseidon_packed(poseidon, PoseidonWords(vec![block_response, account_response.0])),
        keccak256([block_number.to_be_bytes().to_vec(), account_response.1].concat()).into(),
    )
}

#[derive(Clone, Debug)]
pub struct NativeStorageResponse<F: FieldExt> {
    pub storage_root: PoseidonWords<F>,
    pub slot: PoseidonWords<F>,
    pub value: PoseidonWords<F>,
}

/// Computes
/// ```
/// storage_response = hash(storageRoot . slot . value)
/// ```
/// where `hash` is {Poseidon, Keccak} and `value` is left padded to 32 bytes.
pub fn get_storage_response<F: FieldExt, const T: usize, const RATE: usize>(
    poseidon: &mut Poseidon<F, F, T, RATE>,
    input: &EthStorageInput,
) -> ((F, Vec<u8>), NativeStorageResponse<F>) {
    assert_eq!(input.storage_pfs.len(), 1);
    let (slot, _value, proof) = input.storage_pfs.last().unwrap();
    let storage_root = proof.root_hash;
    let mut value = [0u8; 32];
    _value.to_big_endian(&mut value);

    let response_keccak = [slot.as_bytes(), &value[..]].concat();
    let [storage_root, slot, value] =
        [storage_root.as_bytes(), slot.as_bytes(), &value[..]].map(bytes_to_poseidon_words);
    let response_poseidon = poseidon_packed(poseidon, storage_root.concat(&slot).concat(&value));
    ((response_poseidon, response_keccak), NativeStorageResponse { storage_root, slot, value })
}

/// Computes
/// ```
/// hash(block_response . account_response . storage_response)
/// ```
pub fn get_full_storage_response<F: FieldExt, const T: usize, const RATE: usize>(
    poseidon: &mut Poseidon<F, F, T, RATE>,
    block_response: (F, u32),
    account_response: (F, Address),
    storage_response: (F, Vec<u8>),
) -> (F, H256) {
    (
        poseidon_packed(
            poseidon,
            PoseidonWords(vec![block_response.0, account_response.0, storage_response.0]),
        ),
        keccak256(
            [&block_response.1.to_be_bytes(), account_response.1.as_bytes(), &storage_response.1]
                .concat(),
        )
        .into(),
    )
}

// PoseidonWords with NativeLoader
pub(crate) fn bytes_to_poseidon_words<F: FieldExt>(bytes: &[u8]) -> PoseidonWords<F> {
    PoseidonWords(if bytes.is_empty() {
        vec![]
    } else if bytes.len() < 32 {
        vec![evaluate_bytes(bytes)]
    } else {
        bytes.chunks(16).map(evaluate_bytes).collect()
    })
}

/// Assumes `F::from_repr` uses little endian.
pub(crate) fn evaluate_bytes<F: FieldExt>(bytes_be: &[u8]) -> F {
    let mut bytes_le = F::Repr::default();
    assert!(bytes_be.len() < bytes_le.as_ref().len());
    for (le, be) in bytes_le.as_mut().iter_mut().zip(bytes_be.iter().rev()) {
        *le = *be;
    }
    F::from_repr(bytes_le).unwrap()
}

/// Query for a block header, optional account state, and optional storage proof(s).
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullStorageQuery {
    pub block_number: u64,
    pub addr_slots: Option<(Address, Vec<H256>)>,
}

/// Response with a block header, optional account state, and optional storage proof(s).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullStorageResponse {
    /// Assumes `block` is an existing block, not a pending block.
    pub block: Block<H256>,
    pub account_storage: Option<EthStorageInput>,
}

impl From<FullStorageResponse> for EthBlockStorageInput {
    fn from(value: FullStorageResponse) -> Self {
        let number = value.block.number.unwrap();
        let block_hash = value.block.hash.unwrap();
        let block_header = get_block_rlp(&value.block);
        Self {
            block: value.block,
            block_number: number.as_u32(),
            block_hash,
            block_header,
            storage: value.account_storage.unwrap_or_else(|| DEFAULT_STORAGE_QUERY.clone()),
        }
    }
}

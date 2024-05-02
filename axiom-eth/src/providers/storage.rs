use ethers_core::{
    types::{Address, Bytes, EIP1186ProofResponse, H256},
    utils::keccak256,
};
use ethers_providers::{JsonRpcClient, Middleware, Provider};
use futures::future::join_all;
use rlp::{Encodable, Rlp, RlpStream};
use tokio::runtime::Runtime;
use zkevm_hashes::util::eth_types::ToBigEndian;

use crate::{
    mpt::{MPTInput, KECCAK_RLP_EMPTY_STRING},
    providers::account::get_acct_list,
    storage::{
        circuit::{EthBlockStorageInput, EthStorageInput},
        ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN, STORAGE_PROOF_VALUE_MAX_BYTE_LEN,
    },
};

use super::block::get_block_rlp;

/// stateRoot is not provided and set to H256(0)
pub fn json_to_mpt_input(
    pf: EIP1186ProofResponse,
    acct_pf_max_depth: usize,
    storage_pf_max_depth: usize,
) -> EthStorageInput {
    let addr = pf.address;
    let acct_key = H256(keccak256(addr));
    let slot_is_empty = !is_assigned_slot(&acct_key, &pf.account_proof);
    log::debug!("address: {addr},  account is empty: {slot_is_empty}");
    let acct_state = get_acct_list(&pf);
    // JSON-RPC Provider has been known to provide wrong codeHash vs MPT value, so we extract value from MPT proof itself
    // If the proof ends with a branch node that contains the leaf node, we extract the
    // leaf node and add it to the end of the proof so that our mpt implementation can
    // handle it.
    let get_new_proof_and_value = |key: &H256, proof: &[Bytes]| {
        if proof.is_empty() {
            return (vec![], vec![]);
        }
        let decode = Rlp::new(proof.last().unwrap());
        assert!(decode.is_list());
        let add_leaf = decode.item_count().unwrap() == 17;
        let mut new_proof: Vec<Vec<u8>> = proof.iter().map(|x| x.to_vec()).collect();
        let value;
        if add_leaf {
            let last_nibble = last_nibble(key, proof);
            assert!(last_nibble < 16);
            let leaf = decode.at(last_nibble as usize).unwrap();
            if let Ok(leaf) = leaf.as_list::<Vec<u8>>() {
                if leaf.is_empty() {
                    // this is a non-inclusion proof
                    value = vec![0x80];
                } else {
                    assert_eq!(leaf.len(), 2);
                    value = leaf.last().unwrap().to_vec();
                    let leaf = rlp::encode_list::<Vec<u8>, Vec<u8>>(&leaf).to_vec();
                    new_proof.push(leaf);
                }
            } else {
                value = leaf.as_val().unwrap()
            }
        } else {
            value = decode.val_at(1).unwrap()
        }
        (new_proof, value)
    };
    let (new_acct_pf, mut acct_state_rlp) = get_new_proof_and_value(&acct_key, &pf.account_proof);
    let mut storage_root = pf.storage_hash;
    if slot_is_empty {
        acct_state_rlp = EMPTY_ACCOUNT_RLP.clone();
        // If account is empty, then storage root should be
        // - null root hash = keccak(rlp("")) = keccak(0x80) = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
        storage_root = H256::from_slice(&KECCAK_RLP_EMPTY_STRING);
    }
    let acct_pf = MPTInput {
        path: acct_key.into(),
        value: acct_state_rlp,
        root_hash: H256([0u8; 32]), // STATE ROOT IS UNKNOWN IN THIS FUNCTION AND NOT SET
        proof: new_acct_pf,
        value_max_byte_len: ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
        max_depth: acct_pf_max_depth,
        slot_is_empty,
        max_key_byte_len: 32,
        key_byte_len: None,
    };
    let storage_pfs = pf
        .storage_proof
        .into_iter()
        .map(|storage_pf| {
            let path = H256(keccak256(storage_pf.key.to_be_bytes()));
            let (new_proof, mut value) = get_new_proof_and_value(&path, &storage_pf.proof);
            let new_proof_bytes: Vec<Bytes> =
                new_proof.clone().into_iter().map(Bytes::from_iter).collect();
            let slot_is_empty = !is_assigned_slot(&path, &new_proof_bytes);
            if slot_is_empty {
                value = vec![0x80];
            }
            assert_eq!(&value, storage_pf.value.rlp_bytes().as_ref());
            log::info!(
                "address: {addr}, slot: {}, storage slot is empty: {slot_is_empty}",
                storage_pf.key
            );
            (
                storage_pf.key,
                storage_pf.value,
                MPTInput {
                    path: path.into(),
                    value,
                    root_hash: storage_root,
                    proof: new_proof,
                    value_max_byte_len: STORAGE_PROOF_VALUE_MAX_BYTE_LEN,
                    max_depth: storage_pf_max_depth,
                    slot_is_empty,
                    max_key_byte_len: 32,
                    key_byte_len: None,
                },
            )
        })
        .collect();
    EthStorageInput { addr, acct_state, acct_pf, storage_pfs }
}

/// Does not provide state root
async fn get_storage_query<P: JsonRpcClient>(
    provider: &Provider<P>,
    block_number: u64,
    addr: Address,
    slots: Vec<H256>,
    acct_pf_max_depth: usize,
    storage_pf_max_depth: usize,
) -> EthStorageInput {
    log::debug!("block number: {block_number}");
    let pf = provider.get_proof(addr, slots, Some(block_number.into())).await.unwrap();
    json_to_mpt_input(pf, acct_pf_max_depth, storage_pf_max_depth)
}

pub fn get_storage_queries<P: JsonRpcClient>(
    provider: &Provider<P>,
    queries: Vec<(u64, Address, H256)>,
    acct_pf_max_depth: usize,
    storage_pf_max_depth: usize,
) -> Vec<EthStorageInput> {
    let rt = Runtime::new().unwrap();
    rt.block_on(join_all(queries.into_iter().map(|(block_number, addr, slot)| {
        get_storage_query(
            provider,
            block_number,
            addr,
            vec![slot],
            acct_pf_max_depth,
            storage_pf_max_depth,
        )
    })))
}

pub fn get_block_storage_input<P: JsonRpcClient>(
    provider: &Provider<P>,
    block_number: u32,
    addr: Address,
    slots: Vec<H256>,
    acct_pf_max_depth: usize,
    storage_pf_max_depth: usize,
) -> EthBlockStorageInput {
    let rt = Runtime::new().unwrap();
    let block = rt
        .block_on(provider.get_block(block_number as u64))
        .unwrap()
        .unwrap_or_else(|| panic!("Block {block_number} not found"));
    let block_hash = block.hash.unwrap();
    let block_header = get_block_rlp(&block);

    let mut storage = rt.block_on(get_storage_query(
        provider,
        block_number as u64,
        addr,
        slots,
        acct_pf_max_depth,
        storage_pf_max_depth,
    ));
    storage.acct_pf.root_hash = block.state_root;

    EthBlockStorageInput { block, block_number, block_hash, block_header, storage }
}

pub fn is_assigned_slot(key: &H256, proof: &[Bytes]) -> bool {
    let mut key_nibbles = Vec::new();
    for &byte in key.as_bytes() {
        key_nibbles.push(byte / 16);
        key_nibbles.push(byte % 16);
    }
    let mut key_frags = Vec::new();
    let mut path_idx = 0;
    for node in proof.iter() {
        let rlp = Rlp::new(node);
        if rlp.item_count().unwrap() == 2 {
            let path = rlp.at(0).unwrap().data().unwrap();
            let is_odd = (path[0] / 16 == 1u8) || (path[0] / 16 == 3u8);
            let mut frag = Vec::new();
            if is_odd {
                frag.push(path[0] % 16);
                path_idx += 1;
            }
            for byte in path.iter().skip(1) {
                frag.push(*byte / 16);
                frag.push(*byte % 16);
                path_idx += 2;
            }
            key_frags.extend(frag);
        } else {
            key_frags.extend(vec![key_nibbles[path_idx]]);
            path_idx += 1;
        }
    }
    if path_idx == 64 {
        for idx in 0..64 {
            if key_nibbles[idx] != key_frags[idx] {
                return false;
            }
        }
    } else {
        return false;
    }
    true
}

/// In the case that we have a branch node at the end and we want to
/// read the next node, this tells us which entry to look at.
pub fn last_nibble(key: &H256, proof: &[Bytes]) -> u8 {
    let mut key_nibbles = Vec::new();
    for &byte in key.as_bytes() {
        key_nibbles.push(byte / 16);
        key_nibbles.push(byte % 16);
    }
    let mut key_frags = Vec::new();
    let mut path_idx = 0;
    for node in proof.iter() {
        let rlp = Rlp::new(node);
        if rlp.item_count().unwrap() == 2 {
            let path = rlp.at(0).unwrap().data().unwrap();
            let is_odd = (path[0] / 16 == 1u8) || (path[0] / 16 == 3u8);
            let mut frag = Vec::new();
            if is_odd {
                frag.push(path[0] % 16);
                path_idx += 1;
            }
            for byte in path.iter().skip(1) {
                frag.push(*byte / 16);
                frag.push(*byte % 16);
                path_idx += 2;
            }
            key_frags.extend(frag);
        } else {
            key_frags.extend(vec![key_nibbles[path_idx]]);
            path_idx += 1;
        }
    }
    key_nibbles[path_idx - 1]
}

pub fn empty_account_rlp() -> Vec<u8> {
    let mut rlp = RlpStream::new_list(4);
    rlp.append(&0u8);
    rlp.append(&0u8);
    rlp.append(&H256::from_slice(&KECCAK_RLP_EMPTY_STRING)); // null storageRoot
    rlp.append(&H256::zero());
    rlp.out().to_vec()
}

lazy_static::lazy_static! {
    pub static ref EMPTY_ACCOUNT_RLP: Vec<u8> = empty_account_rlp();
}

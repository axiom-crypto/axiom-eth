#![allow(unused_imports)] // until storage proof is refactored
use crate::{
    block_header::{
        EthBlockHeaderChainInstance, GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
        MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
    },
    util::get_merkle_mountain_range,
    Network,
};
use ethers_core::types::{
    Address, Block, BlockId, BlockId::Number, BlockNumber, EIP1186ProofResponse, StorageProof,
    H256, U256,
};
use ethers_core::utils::keccak256;
use ethers_providers::{Http, Middleware, Provider};
// use halo2_mpt::mpt::{max_branch_lens, max_leaf_lens};
use itertools::Itertools;
use lazy_static::__Deref;
use rlp::{decode, decode_list, RlpStream};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    fs::{self, File},
    io::{Read, Write},
    iter, num,
    path::Path,
};
use tokio::runtime::Runtime;

pub const MAINNET_PROVIDER_URL: &str = "https://mainnet.infura.io/v3/";
pub const GOERLI_PROVIDER_URL: &str = "https://goerli.infura.io/v3/";

/*
#[derive(Clone, Debug, Default)]
pub struct EthBlockAcctStorageInput {
    pub block_hash: (Option<BigUint>, Option<BigUint>),
    pub addr: Option<BigUint>,
    pub slot: (Option<BigUint>, Option<BigUint>),
    pub block_header: Vec<Option<u8>>,

    pub acct_pf_key_bytes: Vec<Option<u8>>,
    pub acct_pf_value_bytes: Vec<Option<u8>>,
    pub acct_pf_value_byte_len: Option<BigUint>,
    pub acct_pf_root_hash_bytes: Vec<Option<u8>>,
    pub acct_pf_leaf_bytes: Vec<Option<u8>>,
    pub acct_pf_nodes: Vec<Vec<Option<u8>>>,
    pub acct_pf_node_types: Vec<Option<u8>>,
    pub acct_pf_depth: Option<BigUint>,
    pub acct_pf_key_frag_hexs: Vec<Vec<Option<u8>>>,
    pub acct_pf_key_frag_is_odd: Vec<Option<u8>>,
    pub acct_pf_key_frag_byte_len: Vec<Option<BigUint>>,
    pub acct_pf_key_byte_len: usize,
    pub acct_pf_value_max_byte_len: usize,
    pub acct_pf_max_depth: usize,

    pub storage_pf_key_bytes: Vec<Option<u8>>,
    pub storage_pf_value_bytes: Vec<Option<u8>>,
    pub storage_pf_value_byte_len: Option<BigUint>,
    pub storage_pf_root_hash_bytes: Vec<Option<u8>>,
    pub storage_pf_leaf_bytes: Vec<Option<u8>>,
    pub storage_pf_nodes: Vec<Vec<Option<u8>>>,
    pub storage_pf_node_types: Vec<Option<u8>>,
    pub storage_pf_depth: Option<BigUint>,
    pub storage_pf_key_frag_hexs: Vec<Vec<Option<u8>>>,
    pub storage_pf_key_frag_is_odd: Vec<Option<u8>>,
    pub storage_pf_key_frag_byte_len: Vec<Option<BigUint>>,
    pub storage_pf_key_byte_len: usize,
    pub storage_pf_value_max_byte_len: usize,
    pub storage_pf_max_depth: usize,

    pub pub_hash: BigUint,
}

pub fn get_block_acct_storage_input(
    provider: &Provider<Http>,
    block_number: u64,
    addr: Address,
    slot: U256,
    acct_pf_max_depth: usize,
    storage_pf_max_depth: usize,
) -> EthBlockAcctStorageInput {
    let acct_pf_key_byte_len = 32;
    let acct_pf_value_max_byte_len = 114;
    let storage_pf_key_byte_len = 32;
    let storage_pf_value_max_byte_len = 33;

    let rt = Runtime::new().unwrap();
    let block = rt.block_on(provider.get_block(block_number)).unwrap().unwrap();
    let block_hash_pre = block.hash.unwrap();
    let mut block_rlp = get_block_rlp(block.clone());
    let header_rlp_max_bytes = match NETWORK {
        Network::Mainnet => MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
        Network::Goerli => GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
    };
    block_rlp.extend(vec![0; header_rlp_max_bytes - block_rlp.len()]);

    let mut slot_bytes = vec![0; 32];
    slot.to_big_endian(&mut slot_bytes);
    let slot_h256 = H256::from_slice(&slot_bytes);
    let pf = rt
        .block_on(provider.get_proof(
            addr,
            vec![slot_h256],
            Some(Number(BlockNumber::from(block_number))),
        ))
        .unwrap();
    //let serialized = serde_json::to_value(pf).unwrap();
    //let pf2: EIP1186ProofResponse = serde_json::from_value(serialized).unwrap();

    let block_hash = encode_hash(&block_hash_pre);
    let addr_out = encode_addr(&addr);
    let slot_out = encode_u256(&slot);
    let block_header: Vec<Option<u8>> = block_rlp.into_iter().map(Some).collect();

    let acct_pf = pf.account_proof.clone();
    let (_, acct_pf_max_leaf_bytes) =
        max_leaf_lens(acct_pf_key_byte_len, acct_pf_value_max_byte_len);
    let (_, acct_pf_max_branch_bytes) = max_branch_lens();
    let acct_pf_key_bytes: Vec<u8> = keccak256(addr).to_vec();
    let mut acct_pf_value_bytes = get_acct_rlp(&pf);
    let acct_pf_value_byte_len = acct_pf_value_bytes.len();
    acct_pf_value_bytes.extend(vec![0; acct_pf_value_max_byte_len - acct_pf_value_byte_len]);
    let acct_pf_root_hash_bytes: Vec<u8> = block.state_root.as_bytes().iter().map(|x| *x).collect();
    let mut acct_pf_leaf_bytes: Vec<u8> = acct_pf[acct_pf.len() - 1].iter().map(|x| *x).collect();
    acct_pf_leaf_bytes.extend(vec![0; acct_pf_max_leaf_bytes - acct_pf_leaf_bytes.len()]);
    let mut acct_pf_nodes = Vec::new();
    let mut acct_pf_node_types: Vec<u8> = Vec::new();
    let mut acct_pf_key_frag_hexs: Vec<Vec<u8>> = Vec::new();
    let mut acct_pf_key_frag_is_odd: Vec<u8> = Vec::new();
    let mut acct_pf_key_frag_byte_len: Vec<BigUint> = Vec::new();
    let key_hexs =
        acct_pf_key_bytes.iter().map(|x| vec![x / 16, x % 16]).collect::<Vec<Vec<u8>>>().concat();
    let mut hex_idx = 0;
    for idx in 0..acct_pf_max_depth {
        if idx < acct_pf.len() - 1 {
            let mut node = acct_pf[idx].to_vec();
            node.extend(vec![0; acct_pf_max_branch_bytes - node.len()]);
            acct_pf_nodes.push(node);
        } else if idx < acct_pf_max_depth - 1 {
            let dummy_branch_str =
        "f1808080808080808080808080808080a0000000000000000000000000000000000000000000000000000000000000000080";
            let mut node = Vec::from_hex(dummy_branch_str).unwrap();
            node.extend(vec![0; acct_pf_max_branch_bytes - node.len()]);
            acct_pf_nodes.push(node);
        }
        let mut node_type = 0;
        if idx < acct_pf.len() {
            let decode: Vec<Vec<u8>> = decode_list(&acct_pf[idx]);
            if decode.len() == 2 {
                if idx < acct_pf.len() - 1 {
                    node_type = 1;
                }
                let hexs = decode[0]
                    .iter()
                    .map(|x| vec![x / 16, x % 16])
                    .collect::<Vec<Vec<u8>>>()
                    .concat();
                if hexs[0] % 2 == 0 {
                    let mut hex_push: Vec<u8> = hexs[2..].to_vec();
                    hex_idx += hex_push.len();
                    hex_push.extend(vec![0; 64 - hex_push.len()]);
                    acct_pf_key_frag_hexs.push(hex_push);
                    acct_pf_key_frag_is_odd.push(0);
                } else {
                    let mut hex_push: Vec<u8> = hexs[1..].to_vec();
                    hex_idx += hex_push.len();
                    hex_push.extend(vec![0; 64 - hex_push.len()]);
                    acct_pf_key_frag_hexs.push(hex_push);
                    acct_pf_key_frag_is_odd.push(1);
                }
                acct_pf_key_frag_byte_len.push(BigUint::from(decode[0].len()));
            } else {
                let mut hex_push: Vec<u8> = vec![key_hexs[hex_idx]];
                hex_idx += 1;
                hex_push.extend(vec![0; 63]);
                acct_pf_key_frag_hexs.push(hex_push);
                acct_pf_key_frag_is_odd.push(1);
                acct_pf_key_frag_byte_len.push(BigUint::from(1u64));
            }
        } else {
            acct_pf_key_frag_hexs.push(vec![0; 64]);
            acct_pf_key_frag_is_odd.push(0);
            acct_pf_key_frag_byte_len.push(BigUint::from(0u64));
        }
        if idx < acct_pf_max_depth - 1 {
            acct_pf_node_types.push(node_type);
        }
    }
    let acct_pf_depth = acct_pf.len();

    let storage_pf = pf.storage_proof[0].clone();
    let (_, storage_pf_max_leaf_bytes) =
        max_leaf_lens(storage_pf_key_byte_len, storage_pf_value_max_byte_len);
    let (_, storage_pf_max_branch_bytes) = max_branch_lens();
    let storage_pf_key_bytes: Vec<u8> = keccak256(storage_pf.key).to_vec();
    let storage_pf_root_hash_bytes: Vec<u8> = pf.storage_hash.as_bytes().to_vec();
    let mut storage_pf_leaf_bytes: Vec<u8> = storage_pf.proof[storage_pf.proof.len() - 1].to_vec();
    let decode_leaf: Vec<Vec<u8>> = decode_list(&storage_pf_leaf_bytes);
    let mut storage_pf_value_bytes = decode_leaf[1].clone();
    let storage_pf_value_byte_len = storage_pf_value_bytes.len();
    storage_pf_value_bytes
        .extend(vec![0; storage_pf_value_max_byte_len - storage_pf_value_byte_len]);
    storage_pf_leaf_bytes.extend(vec![0; storage_pf_max_leaf_bytes - storage_pf_leaf_bytes.len()]);
    let mut storage_pf_nodes = Vec::new();
    let mut storage_pf_node_types: Vec<u8> = Vec::new();
    let mut storage_pf_key_frag_hexs: Vec<Vec<u8>> = Vec::new();
    let mut storage_pf_key_frag_is_odd: Vec<u8> = Vec::new();
    let mut storage_pf_key_frag_byte_len: Vec<BigUint> = Vec::new();
    let key_hexs = storage_pf_key_bytes
        .iter()
        .map(|x| vec![x / 16, x % 16])
        .collect::<Vec<Vec<u8>>>()
        .concat();
    let mut hex_idx = 0;
    for idx in 0..storage_pf_max_depth {
        if idx < storage_pf.proof.len() - 1 {
            let mut node = storage_pf.proof[idx].to_vec();
            node.extend(vec![0; storage_pf_max_branch_bytes - node.len()]);
            storage_pf_nodes.push(node);
        } else if idx < storage_pf_max_depth - 1 {
            let dummy_branch_str =
        "f1808080808080808080808080808080a0000000000000000000000000000000000000000000000000000000000000000080";
            let mut node = Vec::from_hex(dummy_branch_str).unwrap();
            node.extend(vec![0; storage_pf_max_branch_bytes - node.len()]);
            storage_pf_nodes.push(node);
        }
        let mut node_type = 0;
        if idx < storage_pf.proof.len() {
            let decode: Vec<Vec<u8>> = decode_list(&storage_pf.proof[idx]);
            if decode.len() == 2 {
                if idx < storage_pf.proof.len() - 1 {
                    node_type = 1;
                }
                let hexs = decode[0]
                    .iter()
                    .map(|x| vec![x / 16, x % 16])
                    .collect::<Vec<Vec<u8>>>()
                    .concat();
                if hexs[0] % 2 == 0 {
                    let mut hex_push: Vec<u8> = hexs[2..].to_vec();
                    hex_idx += hex_push.len();
                    hex_push.extend(vec![0; 64 - hex_push.len()]);
                    storage_pf_key_frag_hexs.push(hex_push);
                    storage_pf_key_frag_is_odd.push(0);
                } else {
                    let mut hex_push: Vec<u8> = hexs[1..].to_vec();
                    hex_idx += hex_push.len();
                    hex_push.extend(vec![0; 64 - hex_push.len()]);
                    storage_pf_key_frag_hexs.push(hex_push);
                    storage_pf_key_frag_is_odd.push(1);
                }
                storage_pf_key_frag_byte_len.push(BigUint::from(decode[0].len()));
            } else {
                let mut hex_push: Vec<u8> = vec![key_hexs[hex_idx]];
                hex_idx += 1;
                hex_push.extend(vec![0; 63]);
                storage_pf_key_frag_hexs.push(hex_push);
                storage_pf_key_frag_is_odd.push(1);
                storage_pf_key_frag_byte_len.push(BigUint::from(1u64));
            }
        } else {
            storage_pf_key_frag_hexs.push(vec![0; 64]);
            storage_pf_key_frag_is_odd.push(0);
            storage_pf_key_frag_byte_len.push(BigUint::from(0u64));
        }
        if idx < storage_pf_max_depth - 1 {
            storage_pf_node_types.push(node_type);
        }
    }
    let storage_pf_depth = storage_pf.proof.len();

    let mut hasher = Keccak256::default();
    let mut hash_inp = Vec::with_capacity(120);
    hash_inp.extend_from_slice(block_hash_pre.as_bytes());
    hash_inp.extend_from_slice(addr.as_bytes());
    let mut slot_bytes = [0u8; 32];
    slot.to_big_endian(&mut slot_bytes);
    hash_inp.extend(slot_bytes);
    let mut block_number_bytes = (block_number as u32).to_be_bytes().to_vec();
    while block_number_bytes.len() > 1 && block_number_bytes[0] == 0 {
        block_number_bytes.drain(..1);
    }
    block_number_bytes.extend(vec![0; 4 - block_number_bytes.len()]);
    hash_inp.extend(block_number_bytes);
    let mut slot_value = Vec::with_capacity(32);
    slot_value.extend_from_slice(&decode_leaf[1][1..]);
    slot_value.extend(vec![0; 32 - slot_value.len()]);
    hash_inp.extend(slot_value);
    dbg!(hex::encode(&hash_inp));
    hasher.update(hash_inp);
    let pub_hash = hasher.finalize().to_vec();
    dbg!(BigUint::from_bytes_be(&pub_hash).to_str_radix(16));
    let pub_hash = BigUint::from_bytes_be(&pub_hash[..31]);

    EthBlockAcctStorageInput {
        block_hash: (Some(block_hash.0.clone()), Some(block_hash.1.clone())),
        addr: Some(addr_out),
        slot: (Some(slot_out.0.clone()), Some(slot_out.1.clone())),
        block_header,

        acct_pf_key_bytes: acct_pf_key_bytes.into_iter().map(Some).collect(),
        acct_pf_value_bytes: acct_pf_value_bytes.into_iter().map(Some).collect(),
        acct_pf_value_byte_len: Some(BigUint::from(acct_pf_value_byte_len)),
        acct_pf_root_hash_bytes: acct_pf_root_hash_bytes.into_iter().map(Some).collect(),
        acct_pf_leaf_bytes: acct_pf_leaf_bytes.into_iter().map(Some).collect(),
        acct_pf_nodes: acct_pf_nodes
            .into_iter()
            .map(|x| x.into_iter().map(Some).collect())
            .collect(),
        acct_pf_node_types: acct_pf_node_types.into_iter().map(Some).collect(),
        acct_pf_depth: Some(BigUint::from(acct_pf_depth)),
        acct_pf_key_frag_hexs: acct_pf_key_frag_hexs
            .into_iter()
            .map(|x| x.into_iter().map(Some).collect())
            .collect(),
        acct_pf_key_frag_is_odd: acct_pf_key_frag_is_odd.into_iter().map(Some).collect(),
        acct_pf_key_frag_byte_len: acct_pf_key_frag_byte_len.into_iter().map(Some).collect(),
        acct_pf_key_byte_len,
        acct_pf_value_max_byte_len,
        acct_pf_max_depth,

        storage_pf_key_bytes: storage_pf_key_bytes.into_iter().map(Some).collect(),
        storage_pf_value_bytes: storage_pf_value_bytes.into_iter().map(Some).collect(),
        storage_pf_value_byte_len: Some(BigUint::from(storage_pf_value_byte_len)),
        storage_pf_root_hash_bytes: storage_pf_root_hash_bytes.into_iter().map(Some).collect(),
        storage_pf_leaf_bytes: storage_pf_leaf_bytes.into_iter().map(Some).collect(),
        storage_pf_nodes: storage_pf_nodes
            .into_iter()
            .map(|x| x.into_iter().map(Some).collect())
            .collect(),
        storage_pf_node_types: storage_pf_node_types.into_iter().map(Some).collect(),
        storage_pf_depth: Some(BigUint::from(storage_pf_depth)),
        storage_pf_key_frag_hexs: storage_pf_key_frag_hexs
            .into_iter()
            .map(|x| x.into_iter().map(Some).collect())
            .collect(),
        storage_pf_key_frag_is_odd: storage_pf_key_frag_is_odd.into_iter().map(Some).collect(),
        storage_pf_key_frag_byte_len: storage_pf_key_frag_byte_len.into_iter().map(Some).collect(),
        storage_pf_key_byte_len,
        storage_pf_value_max_byte_len,
        storage_pf_max_depth,
        pub_hash,
    }
}

pub fn get_acct_rlp(pf: &EIP1186ProofResponse) -> Vec<u8> {
    let mut rlp: RlpStream = RlpStream::new_list(4);
    rlp.append(&pf.nonce);
    rlp.append(&pf.balance);
    rlp.append(&pf.storage_hash);
    rlp.append(&pf.code_hash);
    rlp.out().into()
}
*/

pub fn get_block_rlp(block: Block<H256>) -> Vec<u8> {
    let mut rlp = RlpStream::new_list(16);
    rlp.append(&block.parent_hash);
    rlp.append(&block.uncles_hash);
    rlp.append(&block.author.unwrap());
    rlp.append(&block.state_root);
    rlp.append(&block.transactions_root);
    rlp.append(&block.receipts_root);
    rlp.append(&block.logs_bloom.unwrap());
    rlp.append(&block.difficulty);
    rlp.append(&block.number.unwrap());
    rlp.append(&block.gas_limit);
    rlp.append(&block.gas_used);
    rlp.append(&block.timestamp);
    rlp.append(&block.extra_data.to_vec());
    rlp.append(&block.mix_hash.unwrap());
    rlp.append(&block.nonce.unwrap());
    rlp.append(&block.base_fee_per_gas.unwrap());
    rlp.out().into()
}

/// returns tuple of:
///   * vector of RLP bytes of each block
///   * tuple of  
///       * parentHash (H256)
///       * endHash (H256)
///       * startBlockNumber (u32)
///       * endBlockNumber (u32)
///       * merkleRoots (Vec<H256>)
///   * where merkleRoots is a length `max_depth + 1` vector representing a merkle mountain range, ordered largest mountain first
pub fn get_blocks_input(
    provider: &Provider<Http>,
    start_block_number: u32,
    num_blocks: u32,
    max_depth: usize,
) -> (Vec<Vec<u8>>, EthBlockHeaderChainInstance) {
    assert!(num_blocks <= (1 << max_depth));
    fs::create_dir_all("./data/headers").unwrap();
    let end_block_number = start_block_number + num_blocks - 1;
    let rt = Runtime::new().unwrap();
    let chain_id = rt.block_on(provider.get_chainid()).unwrap();
    let path = format!(
        "./data/headers/chainid{chain_id}_{start_block_number:06x}_{end_block_number:06x}.dat"
    );

    let (mut block_rlps, block_hashes, prev_hash) = if let Ok(f) = File::open(path.as_str()) {
        bincode::deserialize_from(f).unwrap()
    } else {
        let mut block_rlps = Vec::with_capacity(max_depth);
        let mut block_hashes = Vec::with_capacity(num_blocks as usize);
        let mut prev_hash = H256::zero();

        for block_number in start_block_number..start_block_number + num_blocks {
            let block = rt
                .block_on(provider.get_block(block_number as u64))
                .expect("get_block JSON-RPC call")
                .unwrap_or_else(|| panic!("block {block_number} should exist"));
            if block_number == start_block_number {
                prev_hash = block.parent_hash;
            }
            block_hashes.push(block.hash.unwrap());
            block_rlps.push(get_block_rlp(block));
        }
        // write this to file
        let file = File::create(path.as_str()).unwrap();
        let payload = (block_rlps, block_hashes, prev_hash);
        bincode::serialize_into(file, &payload).unwrap();
        payload
    };
    // pad to correct length with dummies
    let dummy_block_rlp = block_rlps[0].clone();
    block_rlps.resize(1 << max_depth, dummy_block_rlp);

    let end_hash = *block_hashes.last().unwrap();
    let mmr = get_merkle_mountain_range(&block_hashes, max_depth);

    let instance = EthBlockHeaderChainInstance::new(
        prev_hash,
        end_hash,
        start_block_number,
        end_block_number,
        mmr,
    );
    (block_rlps, instance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infura() {
        let infura_id =
            fs::read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
        let provider = Provider::<Http>::try_from(
            format!("https://mainnet.infura.io/v3/{infura_id}").as_str(),
        )
        .expect("could not instantiate HTTP Provider");

        let rt = Runtime::new().unwrap();
        let block = rt.block_on(provider.get_block(0xef0000)).unwrap().unwrap();
        assert_eq!(hex::encode(get_block_rlp(block)), "f90201a09ed65266c0958d1ba3e3be4329b41ef541391f2db0f53b99506ae1df5db86ab0a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794388c818ca8b9251b393131c08a736a67ccb19297a0771bced6d4acaab391f3996cfb5f6475b6218759efefab7da25f77f01567446aa0339e9acc250d8aa0f041cb9f428dd18ceef89386d0c18a595bf3103caa3a4175a0371131531246fd6b266a67377943fd3ee59d82eb31c0cec6f3d76cc5421c52c2b90100bcfe8a0b973288ca19f84674b03bb7bd6350074141ae9a788099b462dd6e921a92c415f702493ac86038dcb95ab707011310e2bfca23785102478001a07eb45a03d0db880e59b17a6b06acfa006b616804f4cf97a54b164a8e029fc7cd3f9515b3400de03bc76c683d471524493149de2ae00672a27304622034819b9008044ccab685da2b2e911aa44ac8c487904834a66b743917cc267f60f4004660938122bfe1bb83424be44c1ce34af7c501a88a058466e600ebae7391e43947240b80524d52392790f263d9c85a4ae66a3ce7f73a884b4a34df06559084192fc260340a0d33663e4808450412bcbf1363dda86450b89f6f294db842e34518a84b52b4228083ef00008401c9c38083cf055784633a003780a06d81c46262890668551c0a5d37a3ecb03d6e3cc6741a7637a0043c611b3dc8658800000000000000008502615e4790");
    }
}

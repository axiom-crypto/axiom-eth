#![allow(unused_imports)] // until storage proof is refactored
use crate::{
    block_header::{
        EthBlockHeaderChainInstance, GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
        MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
    },
    mpt::MPTFixedKeyInput,
    storage::{EthBlockStorageInput, EthStorageInput},
    util::{get_merkle_mountain_range, u256_to_bytes32_be},
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
use rlp::{decode, decode_list, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
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

const ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN: usize = 114;
const STORAGE_PROOF_VALUE_MAX_BYTE_LEN: usize = 33;

pub fn get_block_storage_input(
    provider: &Provider<Http>,
    block_number: u32,
    addr: Address,
    slots: Vec<H256>,
    acct_pf_max_depth: usize,
    storage_pf_max_depth: usize,
) -> EthBlockStorageInput {
    let rt = Runtime::new().unwrap();
    let block = rt.block_on(provider.get_block(block_number as u64)).unwrap().unwrap();
    let block_hash = block.hash.unwrap();
    let block_header = get_block_rlp(&block);

    let pf = rt
        .block_on(provider.get_proof(addr, slots, Some(Number(BlockNumber::from(block_number)))))
        .unwrap();

    for storage_pf in pf.storage_proof.iter() {
        println!("key: {:?}, is_assigned_slot: {}", storage_pf.key, is_assigned_slot(&storage_pf));
    }

    let acct_pf = MPTFixedKeyInput {
        path: H256(keccak256(addr)),
        value: get_acct_rlp(&pf),
        root_hash: block.state_root,
        proof: pf.account_proof.into_iter().map(|x| x.to_vec()).collect(),
        value_max_byte_len: ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
        max_depth: acct_pf_max_depth,
    };

    let storage_pfs = pf
        .storage_proof
        .into_iter()
        .map(|storage_pf| {
            (
                storage_pf.key,
                storage_pf.value,
                MPTFixedKeyInput {
                    path: H256(keccak256(storage_pf.key)),
                    value: storage_pf.value.rlp_bytes().to_vec(),
                    root_hash: pf.storage_hash,
                    proof: storage_pf.proof.into_iter().map(|x| x.to_vec()).collect(),
                    value_max_byte_len: STORAGE_PROOF_VALUE_MAX_BYTE_LEN,
                    max_depth: storage_pf_max_depth,
                },
            )
        })
        .collect();

    EthBlockStorageInput {
        block,
        block_number,
        block_hash,
        block_header,
        storage: EthStorageInput { addr, acct_pf, storage_pfs },
    }
}

pub fn is_assigned_slot(pf: &StorageProof) -> bool {
    let key = keccak256(pf.key);
    let mut key_nibbles = Vec::new();
    for byte in key {
        key_nibbles.push(byte / 16);
        key_nibbles.push(byte % 16);
    }
    let mut key_frags = Vec::new();
    let mut path_idx = 0;
    for node in pf.proof.iter() {
        let rlp = Rlp::new(node);
        if rlp.item_count().unwrap() == 2 {
            let path = rlp.at(0).unwrap().data().unwrap();
            let is_odd = (path[0] / 16 == 1u8) || (path[0] / 16 == 3u8);
            let mut frag = Vec::new();
            if is_odd {
                frag.push(path[0] % 16);
                path_idx += 1;
            }
            for idx in 1..path.len() {
                frag.push(path[idx] / 16);
                frag.push(path[idx] % 16);
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

pub fn get_acct_rlp(pf: &EIP1186ProofResponse) -> Vec<u8> {
    let mut rlp: RlpStream = RlpStream::new_list(4);
    rlp.append(&pf.nonce);
    rlp.append(&pf.balance);
    rlp.append(&pf.storage_hash);
    rlp.append(&pf.code_hash);
    rlp.out().into()
}

pub fn get_block_rlp(block: &Block<H256>) -> Vec<u8> {
    let base_fee = block.base_fee_per_gas;
    let mut rlp = RlpStream::new_list(15 + usize::from(base_fee.is_some()));
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
    base_fee.map(|base_fee| rlp.append(&base_fee));
    rlp.out().into()
}

serde_with::serde_conv!(
    BytesBase64,
    Vec<u8>,
    |bytes: &Vec<u8>| {
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD.encode(bytes)
    },
    |encoded: String| {
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD.decode(encoded)
    }
);

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessedBlock {
    #[serde_as(as = "Vec<BytesBase64>")]
    pub block_rlps: Vec<Vec<u8>>,
    pub block_hashes: Vec<H256>,
    pub prev_hash: H256,
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
        "./data/headers/chainid{chain_id}_{start_block_number:06x}_{end_block_number:06x}.json"
    );

    let ProcessedBlock { mut block_rlps, block_hashes, prev_hash } =
        if let Ok(f) = File::open(path.as_str()) {
            serde_json::from_reader(f).unwrap()
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
                block_rlps.push(get_block_rlp(&block));
            }
            // write this to file
            let file = File::create(path.as_str()).unwrap();
            let payload = ProcessedBlock { block_rlps, block_hashes, prev_hash };
            serde_json::to_writer(file, &payload).unwrap();
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
        assert_eq!(hex::encode(get_block_rlp(&block)), "f90201a09ed65266c0958d1ba3e3be4329b41ef541391f2db0f53b99506ae1df5db86ab0a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794388c818ca8b9251b393131c08a736a67ccb19297a0771bced6d4acaab391f3996cfb5f6475b6218759efefab7da25f77f01567446aa0339e9acc250d8aa0f041cb9f428dd18ceef89386d0c18a595bf3103caa3a4175a0371131531246fd6b266a67377943fd3ee59d82eb31c0cec6f3d76cc5421c52c2b90100bcfe8a0b973288ca19f84674b03bb7bd6350074141ae9a788099b462dd6e921a92c415f702493ac86038dcb95ab707011310e2bfca23785102478001a07eb45a03d0db880e59b17a6b06acfa006b616804f4cf97a54b164a8e029fc7cd3f9515b3400de03bc76c683d471524493149de2ae00672a27304622034819b9008044ccab685da2b2e911aa44ac8c487904834a66b743917cc267f60f4004660938122bfe1bb83424be44c1ce34af7c501a88a058466e600ebae7391e43947240b80524d52392790f263d9c85a4ae66a3ce7f73a884b4a34df06559084192fc260340a0d33663e4808450412bcbf1363dda86450b89f6f294db842e34518a84b52b4228083ef00008401c9c38083cf055784633a003780a06d81c46262890668551c0a5d37a3ecb03d6e3cc6741a7637a0043c611b3dc8658800000000000000008502615e4790");
    }
}

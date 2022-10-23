use eth_types::{
    H256
};
use ethers_core::types::{
    Address, Block, BlockId, BlockId::Number, BlockNumber, EIP1186ProofResponse, StorageProof, U256, 
};
use hex::FromHex;
use ethers_core::utils::keccak256;
use ethers_providers::{Http, Middleware, Provider};
use lazy_static::__Deref;
use num_bigint::{BigUint};
use rlp::{decode, decode_list, RlpStream};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    convert::TryFrom,
    fs::{self, File},
    io::{Read, Write},
    num,
    path::Path,
};
use tokio::runtime::Runtime;

use crate::{
    mpt::mpt::{max_branch_lens, max_leaf_lens},
};

pub fn encode_hash(hash: &H256) -> (BigUint, BigUint) {
    let bytes = hash.as_bytes();
    let val1 = BigUint::from_bytes_be(&bytes[..16]);
    let val2 = BigUint::from_bytes_be(&bytes[16..]);
    (val1, val2)
}

pub fn encode_u256(input: &U256) -> (BigUint, BigUint) {
    let mut bytes = vec![0; 32];
    input.to_big_endian(&mut bytes);
    let val1 = BigUint::from_bytes_be(&bytes[..16]);
    let val2 = BigUint::from_bytes_be(&bytes[16..]);
    (val1, val2)
}

pub fn encode_addr(input: &Address) -> BigUint {
    let bytes = input.as_bytes();
    BigUint::from_bytes_be(&bytes)
}

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
    block_rlp.extend(vec![0; 556 - block_rlp.len()]);

    let mut slot_bytes = vec![0; 32];
    slot.to_big_endian(&mut slot_bytes);
    let slot_h256 = H256::from_slice(&slot_bytes);
    let pf = rt.block_on(provider.get_proof(addr, vec![slot_h256], Some(Number(BlockNumber::from(block_number))))).unwrap();
    let serialized = serde_json::to_value(pf).unwrap();
    let pf2: EIP1186ProofResponse = serde_json::from_value(serialized).unwrap();
    
    let block_hash = encode_hash(&block_hash_pre);
    let addr_out = encode_addr(&addr);
    let slot_out = encode_u256(&slot);
    let block_header: Vec<Option<u8>> = block_rlp.iter().map(|x| Some(*x)).collect();

    let acct_pf = pf2.account_proof.clone();
    let (_, acct_pf_max_leaf_bytes) = max_leaf_lens(acct_pf_key_byte_len, acct_pf_value_max_byte_len);
    let (_, acct_pf_max_branch_bytes) = max_branch_lens();
    let acct_pf_key_bytes: Vec<u8> = keccak256(addr).iter().map(|x| *x).collect();
    let mut acct_pf_value_bytes = get_acct_rlp(&pf2);
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
    let key_hexs = acct_pf_key_bytes.iter().map(|x| vec![x/16, x % 16]).collect::<Vec<Vec<u8>>>().concat();
    let mut hex_idx = 0;
    for idx in 0..acct_pf_max_depth - 1 {
	let mut node: Vec<u8> = Vec::new();
	if idx < acct_pf.len() - 1 {
	    node.extend(acct_pf[idx].iter().map(|x| *x).collect::<Vec<u8>>());
	    node.extend(vec![0; acct_pf_max_branch_bytes - node.len()]);
	    let decode: Vec<Vec<u8>> = decode_list(&acct_pf[idx]);
	    if decode.len() == 2 {
		acct_pf_node_types.push(1);
		let hexs = decode[0].iter().map(|x| vec![x /16, x % 16]).collect::<Vec<Vec<u8>>>().concat();
		if hexs[0] % 2 == 0 {
		    let mut hex_push: Vec<u8> = hexs[2..].iter().map(|x| * x).collect();
		    hex_idx += hex_push.len();
		    hex_push.extend(vec![0; 64 - hex_push.len()]);
		    acct_pf_key_frag_hexs.push(hex_push);
		    acct_pf_key_frag_is_odd.push(0);		    
		} else {
		    let mut hex_push: Vec<u8> = hexs[1..].iter().map(|x| * x).collect();
		    hex_idx += hex_push.len();
		    hex_push.extend(vec![0; 64 - hex_push.len()]);
		    acct_pf_key_frag_hexs.push(hex_push);
		    acct_pf_key_frag_is_odd.push(1);
		}
		acct_pf_key_frag_byte_len.push(BigUint::from(decode[0].len()));
	    } else {
		acct_pf_node_types.push(0);
		let mut hex_push: Vec<u8> = vec![key_hexs[hex_idx]];
		hex_idx += 1;
		hex_push.extend(vec![0; 63]);
		acct_pf_key_frag_hexs.push(hex_push);
		acct_pf_key_frag_is_odd.push(1);
		acct_pf_key_frag_byte_len.push(BigUint::from(1u64));
	    }
	} else {
	    let dummy_branch_str =
		"f1808080808080808080808080808080a0000000000000000000000000000000000000000000000000000000000000000080";
            let mut node2: Vec<u8> =
                Vec::from_hex(dummy_branch_str).unwrap().iter().map(|x| *x).collect();
	    node.extend(node2);
	    node.extend(vec![0; acct_pf_max_branch_bytes - node.len()]);
	    acct_pf_node_types.push(0);
	    acct_pf_key_frag_hexs.push(vec![0; 64]);
	    acct_pf_key_frag_is_odd.push(0);
	    acct_pf_key_frag_byte_len.push(BigUint::from(0u64));	    
	}
	acct_pf_nodes.push(node);
    }
    let mut hexs = key_hexs[hex_idx..].to_vec();
    hexs.extend(vec![0; 64 - hexs.len()]);
    acct_pf_key_frag_hexs.push(hexs);
    if (64 - hex_idx) % 2 == 0 {
	acct_pf_key_frag_is_odd.push(0);
    } else {
	acct_pf_key_frag_is_odd.push(1);
    }
    acct_pf_key_frag_byte_len.push(BigUint::from((64 - hex_idx + 2) / 2));
    let acct_pf_depth = acct_pf.len();
    
    let storage_pf = pf2.storage_proof[0].clone();
    let (_, storage_pf_max_leaf_bytes) = max_leaf_lens(storage_pf_key_byte_len, storage_pf_value_max_byte_len);
    let (_, storage_pf_max_branch_bytes) = max_branch_lens();
    let storage_pf_key_bytes: Vec<u8> = keccak256(storage_pf.key).iter().map(|x| *x).collect();
    let storage_pf_root_hash_bytes: Vec<u8> = pf2.storage_hash.as_bytes().iter().map(|x| *x).collect();
    let mut storage_pf_leaf_bytes: Vec<u8> = storage_pf.proof[storage_pf.proof.len() - 1].iter().map(|x| *x).collect();
    let decode_leaf: Vec<Vec<u8>> = decode_list(&storage_pf_leaf_bytes);
    let mut storage_pf_value_bytes = decode_leaf[1].clone();
    let storage_pf_value_byte_len = storage_pf_value_bytes.len();
    storage_pf_value_bytes.extend(vec![0; storage_pf_value_max_byte_len - storage_pf_value_byte_len]);
    storage_pf_leaf_bytes.extend(vec![0; storage_pf_max_leaf_bytes - storage_pf_leaf_bytes.len()]);
    let mut storage_pf_nodes = Vec::new();
    let mut storage_pf_node_types: Vec<u8> = Vec::new();
    let mut storage_pf_key_frag_hexs: Vec<Vec<u8>> = Vec::new();
    let mut storage_pf_key_frag_is_odd: Vec<u8> = Vec::new();
    let mut storage_pf_key_frag_byte_len: Vec<BigUint> = Vec::new();
    let key_hexs = storage_pf_key_bytes.iter().map(|x| vec![x/16, x % 16]).collect::<Vec<Vec<u8>>>().concat();
    let mut hex_idx = 0;
    for idx in 0..storage_pf_max_depth - 1 {
	let mut node: Vec<u8> = Vec::new();
	if idx < storage_pf.proof.len() - 1 {
	    node.extend(storage_pf.proof[idx].iter().map(|x| *x).collect::<Vec<u8>>());
	    node.extend(vec![0; storage_pf_max_branch_bytes - node.len()]);
	    let decode: Vec<Vec<u8>> = decode_list(&storage_pf.proof[idx]);
	    if decode.len() == 2 {
		storage_pf_node_types.push(1);
		let hexs = decode[0].iter().map(|x| vec![x /16, x % 16]).collect::<Vec<Vec<u8>>>().concat();
		if hexs[0] % 2 == 0 {
		    let mut hex_push: Vec<u8> = hexs[2..].iter().map(|x| * x).collect();
		    hex_idx += hex_push.len();
		    hex_push.extend(vec![0; 64 - hex_push.len()]);
		    storage_pf_key_frag_hexs.push(hex_push);
		    storage_pf_key_frag_is_odd.push(0);		    
		} else {
		    let mut hex_push: Vec<u8> = hexs[1..].iter().map(|x| * x).collect();
		    hex_idx += hex_push.len();
		    hex_push.extend(vec![0; 64 - hex_push.len()]);
		    storage_pf_key_frag_hexs.push(hex_push);
		    storage_pf_key_frag_is_odd.push(1);
		}
		storage_pf_key_frag_byte_len.push(BigUint::from(decode[0].len()));
	    } else {
		storage_pf_node_types.push(0);
		let mut hex_push: Vec<u8> = vec![key_hexs[hex_idx]];
		hex_idx += 1;
		hex_push.extend(vec![0; 63]);
		storage_pf_key_frag_hexs.push(hex_push);
		storage_pf_key_frag_is_odd.push(1);
		storage_pf_key_frag_byte_len.push(BigUint::from(1u64));
	    }
	} else {
	    let dummy_branch_str =
		"f1808080808080808080808080808080a0000000000000000000000000000000000000000000000000000000000000000080";
            let mut node2: Vec<u8> =
                Vec::from_hex(dummy_branch_str).unwrap().iter().map(|x| *x).collect();
	    node.extend(node2);
	    node.extend(vec![0; storage_pf_max_branch_bytes - node.len()]);
	    storage_pf_node_types.push(0);
	    storage_pf_key_frag_hexs.push(vec![0; 64]);
	    storage_pf_key_frag_is_odd.push(0);
	    storage_pf_key_frag_byte_len.push(BigUint::from(0u64));	    
	}
	storage_pf_nodes.push(node);
    }
    let mut hexs = key_hexs[hex_idx..].to_vec();
    hexs.extend(vec![0; 64 - hexs.len()]);
    storage_pf_key_frag_hexs.push(hexs);
    if (64 - hex_idx) % 2 == 0 {
	storage_pf_key_frag_is_odd.push(0);
    } else {
	storage_pf_key_frag_is_odd.push(1);
    }
    storage_pf_key_frag_byte_len.push(BigUint::from((64 - hex_idx + 2) / 2));    
    let storage_pf_depth = storage_pf.proof.len();

    EthBlockAcctStorageInput {
	block_hash: (Some(block_hash.0.clone()), Some(block_hash.1.clone())),
	addr: Some(addr_out),
	slot: (Some(slot_out.0.clone()), Some(slot_out.1.clone())),
	block_header,

	acct_pf_key_bytes: acct_pf_key_bytes.iter().map(|x| Some(*x)).collect(),
	acct_pf_value_bytes: acct_pf_value_bytes.iter().map(|x| Some(*x)).collect(),
	acct_pf_value_byte_len: Some(BigUint::from(acct_pf_value_byte_len)),
	acct_pf_root_hash_bytes: acct_pf_root_hash_bytes.iter().map(|x| Some(*x)).collect(),
	acct_pf_leaf_bytes: acct_pf_leaf_bytes.iter().map(|x| Some(*x)).collect(),
	acct_pf_nodes: acct_pf_nodes.iter().map(|x| x.iter().map(|y| Some(*y)).collect()).collect(),
	acct_pf_node_types: acct_pf_node_types.iter().map(|x| Some(*x)).collect(),
	acct_pf_depth: Some(BigUint::from(acct_pf_depth)),
	acct_pf_key_frag_hexs: acct_pf_key_frag_hexs.iter().map(|x| x.iter().map(|y| Some(*y)).collect()).collect(),
	acct_pf_key_frag_is_odd: acct_pf_key_frag_is_odd.iter().map(|x| Some(*x)).collect(),
	acct_pf_key_frag_byte_len: acct_pf_key_frag_byte_len.iter().map(|x| Some(x.clone())).collect(),
	acct_pf_key_byte_len,
	acct_pf_value_max_byte_len,
	acct_pf_max_depth,
	
	storage_pf_key_bytes: storage_pf_key_bytes.iter().map(|x| Some(*x)).collect(),
	storage_pf_value_bytes: storage_pf_value_bytes.iter().map(|x| Some(*x)).collect(),
	storage_pf_value_byte_len: Some(BigUint::from(storage_pf_value_byte_len)),
	storage_pf_root_hash_bytes: storage_pf_root_hash_bytes.iter().map(|x| Some(*x)).collect(),
	storage_pf_leaf_bytes: storage_pf_leaf_bytes.iter().map(|x| Some(*x)).collect(),
	storage_pf_nodes: storage_pf_nodes.iter().map(|x| x.iter().map(|y| Some(*y)).collect()).collect(),
	storage_pf_node_types: storage_pf_node_types.iter().map(|x| Some(*x)).collect(),
	storage_pf_depth: Some(BigUint::from(storage_pf_depth)),
	storage_pf_key_frag_hexs: storage_pf_key_frag_hexs.iter().map(|x| x.iter().map(|y| Some(*y)).collect()).collect(),
	storage_pf_key_frag_is_odd: storage_pf_key_frag_is_odd.iter().map(|x| Some(*x)).collect(),
	storage_pf_key_frag_byte_len: storage_pf_key_frag_byte_len.iter().map(|x| Some(x.clone())).collect(),
	storage_pf_key_byte_len,
	storage_pf_value_max_byte_len,
	storage_pf_max_depth,	
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

/// returns vector of rlp of each block, and vec![parent hash of starting block, hash of last block, merkle root]
pub fn get_blocks_input(
    provider: &Provider<Http>,
    start_block_number: u64,
    num_blocks: u64,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let path =
        format!("./data/headers/{:06x}_{}.dat", start_block_number + num_blocks - 1, num_blocks);
    let instance_path = format!(
        "./data/headers/{:06x}_{}_instances.dat",
        start_block_number + num_blocks - 1,
        num_blocks
    );

    let mut block_rlps = Vec::with_capacity(num_blocks as usize);
    let mut block_hashes = Vec::with_capacity(num_blocks as usize);
    let mut instance = Vec::with_capacity(3);

    if let Ok(f) = File::open(path.as_str()) {
        block_rlps = bincode::deserialize_from(f).unwrap();
        let f = File::open(instance_path.as_str()).unwrap();
        instance = bincode::deserialize_from(f).unwrap();
        return (block_rlps, instance);
    }

    let rt = Runtime::new().unwrap();
    for block_number in start_block_number..start_block_number + num_blocks {
        let block = rt
            .block_on(provider.get_block(block_number))
            .expect("get_block JSON-RPC call")
            .expect(format!("block {} should exist", block_number).as_str());
        if block_number == start_block_number {
            instance.push(block.parent_hash.as_bytes().to_vec());
        }
        block_hashes.push(block.hash.unwrap().as_bytes().to_vec());
        block_rlps.push(get_block_rlp(block));
    }
    instance.push(block_hashes.last().unwrap().clone());
    instance.push(hash_tree_root(block_hashes));

    // write this to file
    let mut file = File::create(path.as_str()).unwrap();
    bincode::serialize_into(file, &block_rlps).unwrap();
    file = File::create(instance_path.as_str()).unwrap();
    bincode::serialize_into(file, &instance).unwrap();

    (block_rlps, instance)
}

pub fn hash_tree_root(mut leaves: Vec<Vec<u8>>) -> Vec<u8> {
    let depth = leaves.len().ilog2();
    assert_eq!(leaves.len(), 1 << depth);
    for d in (0..depth).rev() {
        for i in 0..(1 << d) {
            let mut hasher = Keccak256::new();
            hasher.update(&[leaves[2 * i].as_slice(), leaves[2 * i + 1].as_slice()].concat());
            leaves[i] = hasher.finalize().to_vec();
        }
    }
    leaves.into_iter().nth(0).unwrap()
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infura() {
        let infura_id =
            fs::read_to_string("scripts/input_gen/INFURA_ID").expect("Infura ID not found");
        let provider = Provider::<Http>::try_from(
            format!("https://mainnet.infura.io/v3/{}", infura_id).as_str(),
        )
        .expect("could not instantiate HTTP Provider");

        let rt = Runtime::new().unwrap();
        let block = rt.block_on(provider.get_block(0xef0000)).unwrap().unwrap();
        assert_eq!(hex::encode(get_block_rlp(block)), "f90201a09ed65266c0958d1ba3e3be4329b41ef541391f2db0f53b99506ae1df5db86ab0a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794388c818ca8b9251b393131c08a736a67ccb19297a0771bced6d4acaab391f3996cfb5f6475b6218759efefab7da25f77f01567446aa0339e9acc250d8aa0f041cb9f428dd18ceef89386d0c18a595bf3103caa3a4175a0371131531246fd6b266a67377943fd3ee59d82eb31c0cec6f3d76cc5421c52c2b90100bcfe8a0b973288ca19f84674b03bb7bd6350074141ae9a788099b462dd6e921a92c415f702493ac86038dcb95ab707011310e2bfca23785102478001a07eb45a03d0db880e59b17a6b06acfa006b616804f4cf97a54b164a8e029fc7cd3f9515b3400de03bc76c683d471524493149de2ae00672a27304622034819b9008044ccab685da2b2e911aa44ac8c487904834a66b743917cc267f60f4004660938122bfe1bb83424be44c1ce34af7c501a88a058466e600ebae7391e43947240b80524d52392790f263d9c85a4ae66a3ce7f73a884b4a34df06559084192fc260340a0d33663e4808450412bcbf1363dda86450b89f6f294db842e34518a84b52b4228083ef00008401c9c38083cf055784633a003780a06d81c46262890668551c0a5d37a3ecb03d6e3cc6741a7637a0043c611b3dc8658800000000000000008502615e4790");
    }
}

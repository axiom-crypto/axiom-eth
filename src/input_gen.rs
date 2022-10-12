use eth_types::H256;
use ethers_core::types::Block;
use ethers_providers::{Http, Middleware, Provider};
use lazy_static::__Deref;
use rlp::RlpStream;
use sha3::{Digest, Keccak256};
use std::{
    convert::TryFrom,
    fs::{self, File},
    io::{Read, Write},
    num,
    path::Path,
};
use tokio::runtime::Runtime;

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

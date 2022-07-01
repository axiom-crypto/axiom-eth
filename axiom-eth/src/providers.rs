use crate::{
    batch_query::response::native::{FullStorageQuery, FullStorageResponse},
    mpt::MPTFixedKeyInput,
    storage::{
        EthBlockStorageInput, EthStorageInput, ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
        ACCOUNT_STATE_FIELDS_MAX_BYTES, STORAGE_PROOF_VALUE_MAX_BYTE_LEN,
    },
};
use ethers_core::types::{Address, Block, Bytes, EIP1186ProofResponse, H256};
use ethers_core::utils::keccak256;
use ethers_providers::{Http, Middleware, Provider, ProviderError};
// use halo2_mpt::mpt::{max_branch_lens, max_leaf_lens};
use futures::future::{join, join_all};
use rlp::{Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{
    fs::{self, File},
    path::PathBuf,
};
use tokio::runtime::Runtime;

pub const MAINNET_PROVIDER_URL: &str = "https://mainnet.infura.io/v3/";
pub const GOERLI_PROVIDER_URL: &str = "https://goerli.infura.io/v3/";

/// Makes concurrent JSON-RPC calls to get the blocks with the given block numbers.
pub fn get_blocks(
    provider: &Provider<Http>,
    block_numbers: impl IntoIterator<Item = u64>,
) -> Result<Vec<Option<Block<H256>>>, ProviderError> {
    let rt = Runtime::new().unwrap();
    rt.block_on(join_all(
        block_numbers.into_iter().map(|block_number| provider.get_block(block_number)),
    ))
    .into_iter()
    .collect()
}

async fn get_account_query(
    provider: &Provider<Http>,
    block_number: u64,
    addr: Address,
    acct_pf_max_depth: usize,
) -> EthStorageInput {
    let block = provider.get_block(block_number).await.unwrap().unwrap();
    let pf = provider.get_proof(addr, vec![], Some(block_number.into())).await.unwrap();

    let acct_key = H256(keccak256(addr));
    let slot_is_empty = !is_assigned_slot(&acct_key, &pf.account_proof);
    EthStorageInput {
        addr,
        acct_state: get_acct_list(&pf),
        acct_pf: MPTFixedKeyInput {
            path: acct_key,
            value: get_acct_rlp(&pf),
            root_hash: block.state_root,
            proof: pf.account_proof.into_iter().map(|x| x.to_vec()).collect(),
            value_max_byte_len: ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
            max_depth: acct_pf_max_depth,
            slot_is_empty,
        },
        storage_pfs: vec![],
    }
}

pub fn get_account_queries(
    provider: &Provider<Http>,
    queries: Vec<(u64, Address)>,
    acct_pf_max_depth: usize,
) -> Vec<EthStorageInput> {
    let rt = Runtime::new().unwrap();
    rt.block_on(join_all(queries.into_iter().map(|(block_number, addr)| {
        get_account_query(provider, block_number, addr, acct_pf_max_depth)
    })))
}

/// Does not provide state root
async fn get_storage_query(
    provider: &Provider<Http>,
    block_number: u64,
    addr: Address,
    slots: Vec<H256>,
    acct_pf_max_depth: usize,
    storage_pf_max_depth: usize,
) -> EthStorageInput {
    let pf = provider.get_proof(addr, slots, Some(block_number.into())).await.unwrap();

    let acct_key = H256(keccak256(addr));
    let slot_is_empty = !is_assigned_slot(&acct_key, &pf.account_proof);
    log::info!("block: {block_number}, address: {addr},  account is empty: {slot_is_empty}");
    let acct_state = get_acct_list(&pf);
    let acct_pf = MPTFixedKeyInput {
        path: acct_key,
        value: get_acct_rlp(&pf),
        root_hash: H256([0u8; 32]),
        proof: pf.account_proof.into_iter().map(|x| x.to_vec()).collect(),
        value_max_byte_len: ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
        max_depth: acct_pf_max_depth,
        slot_is_empty,
    };
    let storage_pfs = pf
        .storage_proof
        .into_iter()
        .map(|storage_pf| {
            let path = H256(keccak256(storage_pf.key));
            let slot_is_empty = !is_assigned_slot(&path, &storage_pf.proof);
            log::info!("block: {block_number}, address: {addr}, slot: {}, storage slot is empty: {slot_is_empty}", storage_pf.key);
            let value = storage_pf.value.rlp_bytes().to_vec();
            (
                storage_pf.key,
                storage_pf.value,
                MPTFixedKeyInput {
                    path,
                    value,
                    root_hash: pf.storage_hash,
                    proof: storage_pf.proof.into_iter().map(|x| x.to_vec()).collect(),
                    value_max_byte_len: STORAGE_PROOF_VALUE_MAX_BYTE_LEN,
                    max_depth: storage_pf_max_depth,
                    slot_is_empty,
                },
            )
        })
        .collect();
    EthStorageInput { addr, acct_state, acct_pf, storage_pfs }
}

pub fn get_full_storage_queries(
    provider: &Provider<Http>,
    queries: Vec<FullStorageQuery>,
    acct_pf_max_depth: usize,
    storage_pf_max_depth: usize,
) -> Result<Vec<FullStorageResponse>, String> {
    let block_futures =
        join_all(queries.iter().map(|query| provider.get_block(query.block_number)));
    let storage_futures =
        queries.into_iter().map(|FullStorageQuery { block_number, addr_slots }| {
            let res = addr_slots.map(|(addr, slots)| {
                get_storage_query(
                    provider,
                    block_number,
                    addr,
                    slots,
                    acct_pf_max_depth,
                    storage_pf_max_depth,
                )
            });
            async {
                match res {
                    Some(res) => Some(res.await),
                    None => None,
                }
            }
        });
    let storage_futures = join_all(storage_futures);
    let (blocks, pfs) =
        Runtime::new().unwrap().block_on(async { join(block_futures, storage_futures).await });
    blocks
        .into_iter()
        .zip(pfs.into_iter())
        .map(|(block, mut pf)| {
            block
                .map_err(|e| format!("get_block JSON-RPC call failed: {e}"))
                .and_then(|block| block.ok_or_else(|| "Block not found".to_string()))
                .map(|block| {
                    if let Some(pf) = pf.as_mut() {
                        pf.acct_pf.root_hash = block.state_root;
                    }
                    FullStorageResponse { block, account_storage: pf }
                })
        })
        .collect::<Result<Vec<_>, _>>()
}

pub fn get_storage_queries(
    provider: &Provider<Http>,
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

pub fn get_block_storage_input(
    provider: &Provider<Http>,
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

pub fn get_acct_rlp(pf: &EIP1186ProofResponse) -> Vec<u8> {
    let mut rlp: RlpStream = RlpStream::new_list(4);
    rlp.append(&pf.nonce);
    rlp.append(&pf.balance);
    rlp.append(&pf.storage_hash);
    rlp.append(&pf.code_hash);
    rlp.out().into()
}

/// Format AccountState into list of fixed-length byte arrays
pub fn get_acct_list(pf: &EIP1186ProofResponse) -> Vec<Vec<u8>> {
    let mut nonce_bytes = vec![0u8; 8];
    pf.nonce.to_big_endian(&mut nonce_bytes);
    let mut balance_bytes = [0u8; 32];
    pf.balance.to_big_endian(&mut balance_bytes);
    let balance_bytes = balance_bytes[32 - ACCOUNT_STATE_FIELDS_MAX_BYTES[1]..].to_vec();
    let storage_root = pf.storage_hash.as_bytes().to_vec();
    let code_hash = pf.code_hash.as_bytes().to_vec();
    vec![nonce_bytes, balance_bytes, storage_root, code_hash]
}

pub fn get_block_rlp(block: &Block<H256>) -> Vec<u8> {
    let withdrawals_root: Option<H256> = block.withdrawals_root;
    let base_fee = block.base_fee_per_gas;
    let rlp_len = 15 + usize::from(base_fee.is_some()) + usize::from(withdrawals_root.is_some());
    let mut rlp = RlpStream::new_list(rlp_len);
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
    withdrawals_root.map(|withdrawals_root| rlp.append(&withdrawals_root));
    let encoding: Vec<u8> = rlp.out().into();
    assert_eq!(keccak256(&encoding), block.hash.unwrap().0);
    encoding
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
// second tuple `instance` is only used for debugging now
pub fn get_blocks_input(
    provider: &Provider<Http>,
    start_block_number: u32,
    num_blocks: u32,
    max_depth: usize,
) -> Vec<Vec<u8>> {
    assert!(num_blocks <= (1 << max_depth));
    assert!(num_blocks > 0);
    let chain_data_dir = PathBuf::from("data/chain");
    fs::create_dir_all(&chain_data_dir).unwrap();
    let end_block_number = start_block_number + num_blocks - 1;
    let rt = Runtime::new().unwrap();
    let chain_id = rt.block_on(provider.get_chainid()).unwrap();
    let path = chain_data_dir
        .join(format!("chainid{chain_id}_{start_block_number:06x}_{end_block_number:06x}.json"));
    // block_hashes and prev_hash no longer used, but keeping this format for compatibility with old cached chaindata
    let ProcessedBlock { mut block_rlps, block_hashes: _, prev_hash: _ } =
        if let Ok(f) = File::open(&path) {
            serde_json::from_reader(f).unwrap()
        } else {
            let blocks = get_blocks(
                provider,
                start_block_number as u64..(start_block_number + num_blocks) as u64,
            )
            .unwrap_or_else(|e| panic!("get_blocks JSON-RPC call failed: {e}"));
            let prev_hash = blocks[0].as_ref().expect("block not found").parent_hash;
            let (block_rlps, block_hashes): (Vec<_>, Vec<_>) = blocks
                .into_iter()
                .map(|block| {
                    let block = block.expect("block not found");
                    (get_block_rlp(&block), block.hash.unwrap())
                })
                .unzip();
            // write this to file
            let file = File::create(&path).unwrap();
            let payload = ProcessedBlock { block_rlps, block_hashes, prev_hash };
            serde_json::to_writer(file, &payload).unwrap();
            payload
        };
    // pad to correct length with dummies
    let dummy_block_rlp = block_rlps[0].clone();
    block_rlps.resize(1 << max_depth, dummy_block_rlp);

    /*let end_hash = *block_hashes.last().unwrap();
    let mmr = get_merkle_mountain_range(&block_hashes, max_depth);

    let instance = EthBlockHeaderChainInstance::new(
        prev_hash,
        end_hash,
        start_block_number,
        end_block_number,
        mmr,
    );*/
    block_rlps
}

#[cfg(test)]
mod tests {
    use std::env::var;

    use super::*;

    #[test]
    fn test_infura() {
        let infura_id = var("INFURA_ID").expect("Infura ID not found");
        let provider = Provider::<Http>::try_from(
            format!("https://mainnet.infura.io/v3/{infura_id}").as_str(),
        )
        .expect("could not instantiate HTTP Provider");

        let rt = Runtime::new().unwrap();
        let block = rt.block_on(provider.get_block(17034973)).unwrap().unwrap();
        assert_eq!(keccak256(get_block_rlp(&block)), block.hash.unwrap().0);
    }
}

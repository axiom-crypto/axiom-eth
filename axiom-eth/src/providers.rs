#![allow(clippy::too_many_arguments)]
use crate::{
    batch_query::response::native::{FullStorageQuery, FullStorageResponse},
    mpt::MPTInput,
    receipt::{calc_max_val_len as rc_calc_max_val_len, EthBlockReceiptInput, EthReceiptInput},
    storage::{
        EthBlockStorageInput, EthStorageInput, ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
        ACCOUNT_STATE_FIELDS_MAX_BYTES, STORAGE_PROOF_VALUE_MAX_BYTE_LEN,
    },
    transaction::{
        calc_max_val_len as tx_calc_max_val_len, EthBlockTransactionInput, EthTransactionInput,
        EthTransactionLenProof, EthTransactionProof,
    },
    Network,
};
use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use ethers_core::types::{
    Address, Block, Bytes, EIP1186ProofResponse, Transaction, TransactionReceipt, H256,
};
use ethers_core::utils::{hex::FromHex, keccak256};
use ethers_providers::{Http, JsonRpcClient, Middleware, Provider, ProviderError, RetryClient};

use futures::future::{join, join_all};
use hasher::HasherKeccak;
use rlp::{Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{
    env::var,
    fs::{self, File},
    path::PathBuf,
    sync::Arc,
};
use tokio::runtime::Runtime;

pub const MAINNET_PROVIDER_URL: &str = "https://mainnet.infura.io/v3/";
pub const GOERLI_PROVIDER_URL: &str = "https://goerli.infura.io/v3/";

pub fn setup_provider(network: Network) -> Provider<RetryClient<Http>> {
    let infura_id = var("INFURA_ID").expect("INFURA_ID environmental variable not set");
    let provider_url = match network {
        Network::Mainnet => format!("{MAINNET_PROVIDER_URL}{infura_id}"),
        Network::Goerli => format!("{GOERLI_PROVIDER_URL}{infura_id}"),
    };
    Provider::new_client(&provider_url, 3, 500).unwrap()
}

/// Makes concurrent JSON-RPC calls to get the blocks with the given block numbers.
pub fn get_blocks<P: JsonRpcClient>(
    provider: &Provider<P>,
    block_numbers: impl IntoIterator<Item = u64>,
) -> Result<Vec<Option<Block<H256>>>, ProviderError> {
    let rt = Runtime::new().unwrap();
    rt.block_on(join_all(
        block_numbers.into_iter().map(|block_number| provider.get_block(block_number)),
    ))
    .into_iter()
    .collect()
}

async fn get_account_query<P: JsonRpcClient>(
    provider: &Provider<P>,
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
        acct_pf: MPTInput {
            path: acct_key.into(),
            value: get_acct_rlp(&pf),
            root_hash: block.state_root,
            proof: pf.account_proof.into_iter().map(|x| x.to_vec()).collect(),
            value_max_byte_len: ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
            max_depth: acct_pf_max_depth,
            slot_is_empty,
            max_key_byte_len: 32,
            key_byte_len: None,
        },
        storage_pfs: vec![],
    }
}

pub fn get_account_queries<P: JsonRpcClient>(
    provider: &Provider<P>,
    queries: Vec<(u64, Address)>,
    acct_pf_max_depth: usize,
) -> Vec<EthStorageInput> {
    let rt = Runtime::new().unwrap();
    rt.block_on(join_all(queries.into_iter().map(|(block_number, addr)| {
        get_account_query(provider, block_number, addr, acct_pf_max_depth)
    })))
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
    let pf = provider.get_proof(addr, slots, Some(block_number.into())).await.unwrap();
    let acct_key = H256(keccak256(addr));
    let slot_is_empty = !is_assigned_slot(&acct_key, &pf.account_proof);
    log::info!("block: {block_number}, address: {addr},  account is empty: {slot_is_empty}");
    let acct_state = get_acct_list(&pf);
    let acct_pf = MPTInput {
        path: acct_key.into(),
        value: get_acct_rlp(&pf),
        root_hash: H256([0u8; 32]),
        proof: pf.account_proof.into_iter().map(|x| x.to_vec()).collect(),
        value_max_byte_len: ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
        max_depth: acct_pf_max_depth,
        slot_is_empty,
        max_key_byte_len: 32,
        key_byte_len: None,
    };
    // If the proof ends with a branch node that contains the leaf node, we extract the
    // leaf node and add it to the end of the proof so that our mpt implementation can
    // handle it.
    let storage_pfs = pf
        .storage_proof
        .into_iter()
        .map(|storage_pf| {
            let path = H256(keccak256(storage_pf.key));
            log::info!("block: {block_number}, address: {addr}, slot: {}, storage slot is empty: {slot_is_empty}", storage_pf.key);
            let value = storage_pf.value.rlp_bytes().to_vec();
            let decode = Rlp::new(&storage_pf.proof[storage_pf.proof.len() - 1]);
            let add_leaf = decode.item_count().unwrap() == 17;
            let mut new_proof: Vec<Vec<u8>> = storage_pf.proof.clone().into_iter().map(|x| x.to_vec()).collect();
            if add_leaf {
                println!("REACHED");
                let last_nibble = last_nibble(&path, &storage_pf.proof);
                assert!(last_nibble < 16);
                let leaf: Vec<Vec<u8>> = decode.list_at(last_nibble as usize).unwrap();
                if leaf.len() > 1 {
                    let leaf = rlp::encode_list::<Vec<u8>, Vec<u8>>(&leaf).to_vec();
                    new_proof.push(leaf);
                }
            }
            let new_proof_bytes: Vec<Bytes> = new_proof.clone().into_iter().map(Bytes::from_iter).collect();
            let slot_is_empty = !is_assigned_slot(&path, &new_proof_bytes);
            (
                storage_pf.key,
                storage_pf.value,
                MPTInput {
                    path: path.into(),
                    value,
                    root_hash: pf.storage_hash,
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

fn from_hex(s: &str) -> Vec<u8> {
    let s = if s.len() % 2 == 1 { format!("0{s}") } else { s.to_string() };
    Vec::from_hex(s).unwrap()
}

async fn get_transaction_query(
    transaction_pf_max_depth: usize,
    transactions: Vec<Transaction>,
    idxs: Vec<usize>,
    transactions_root: H256,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
    constrain_len: bool,
) -> (EthTransactionInput, Option<EthTransactionLenProof>) {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());
    let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
    let num_txs = transactions.len();
    let mut pfs = Vec::new();
    let mut vals_cache = Vec::new();
    for idx in 0..num_txs {
        let tx = transactions[idx].clone();
        let mut tx_key = rlp::encode(&from_hex(&format!("{idx:x}").to_string())).to_vec();
        if idx == 0 {
            tx_key = vec![0x80];
        }
        let tx_rlp = tx.rlp().to_vec();
        trie.insert(tx_key.clone(), tx_rlp.clone()).unwrap();
        vals_cache.push(tx_rlp);
    }
    let root = trie.root().unwrap();
    trie = PatriciaTrie::from(Arc::clone(&memdb), Arc::clone(&hasher), &root).unwrap();
    let root = trie.root().unwrap();
    assert_eq!(&root, transactions_root.as_bytes());

    for idx in idxs {
        let mut tx_key = rlp::encode(&from_hex(&format!("{idx:x}").to_string())).to_vec();
        if idx == 0 {
            tx_key = vec![0x80];
        }
        let tx_rlp = if idx < num_txs { vals_cache[idx].clone() } else { vec![0xba; 32] };
        dbg!(tx_rlp.len());
        let pf = MPTInput {
            path: (&tx_key).into(),
            value: tx_rlp.clone(),
            root_hash: transactions_root,
            proof: trie.get_proof(&tx_key).unwrap(),
            value_max_byte_len: tx_calc_max_val_len(
                max_data_byte_len,
                max_access_list_len,
                enable_types,
            ),
            max_depth: transaction_pf_max_depth,
            slot_is_empty: idx >= num_txs,
            max_key_byte_len: 3,
            key_byte_len: Some(tx_key.len()),
        };
        pfs.push((idx, tx_rlp.clone(), pf));
    }
    let pf0 = if num_txs > 0 {
        let mut tx_key = rlp::encode(&from_hex(&format!("{:x}", num_txs - 1))).to_vec();
        if num_txs == 1 {
            tx_key = vec![0x80];
        }
        let tx_rlp = vals_cache[num_txs - 1].clone();
        EthTransactionProof {
            idx: num_txs - 1,
            proof: MPTInput {
                path: (&tx_key).into(),
                value: tx_rlp,
                root_hash: transactions_root,
                proof: trie.get_proof(&tx_key).unwrap(),
                value_max_byte_len: tx_calc_max_val_len(
                    max_data_byte_len,
                    max_access_list_len,
                    enable_types,
                ),
                max_depth: transaction_pf_max_depth,
                slot_is_empty: false,
                max_key_byte_len: 3,
                key_byte_len: Some(tx_key.len()),
            },
        }
    } else {
        let tx_key = rlp::encode(&from_hex(&format!("{:x}", num_txs + 1))).to_vec();
        let tx_rlp = [0xba; 32].to_vec();
        EthTransactionProof {
            idx: num_txs + 1,
            proof: MPTInput {
                path: (&tx_key).into(),
                value: tx_rlp,
                root_hash: transactions_root,
                proof: trie.get_proof(&tx_key).unwrap(),
                value_max_byte_len: tx_calc_max_val_len(
                    max_data_byte_len,
                    max_access_list_len,
                    enable_types,
                ),
                max_depth: transaction_pf_max_depth,
                slot_is_empty: true,
                max_key_byte_len: 3,
                key_byte_len: Some(tx_key.len()),
            },
        }
    };

    let mut tx_key = rlp::encode(&from_hex(&format!("{num_txs:x}"))).to_vec();
    if num_txs == 0 {
        tx_key = vec![0x80];
    }
    let tx_rlp = [0xba; 2].to_vec();
    let pf1 = EthTransactionProof {
        idx: num_txs,
        proof: MPTInput {
            path: (&tx_key).into(),
            value: tx_rlp,
            root_hash: transactions_root,
            proof: trie.get_proof(&tx_key).unwrap(),
            value_max_byte_len: tx_calc_max_val_len(
                max_data_byte_len,
                max_access_list_len,
                enable_types,
            ),
            max_depth: transaction_pf_max_depth,
            slot_is_empty: true,
            max_key_byte_len: 3,
            key_byte_len: Some(tx_key.len()),
        },
    };
    let len_proof = if constrain_len {
        Some(EthTransactionLenProof { inclusion: pf0, noninclusion: pf1 })
    } else {
        None
    };
    (EthTransactionInput { transaction_pfs: pfs }, len_proof)
}

fn rlp_bytes(receipt: TransactionReceipt) -> Vec<u8> {
    let mut s = RlpStream::new();
    s.begin_list(4);
    if let Some(post_state) = receipt.root {
        s.append(&post_state);
    } else {
        s.append(&receipt.status.expect("No post-state or status in receipt"));
    }
    s.append(&receipt.cumulative_gas_used);
    s.append(&receipt.logs_bloom);
    s.append_list(&receipt.logs);
    let bytesa = s.out();
    let mut rlp = bytesa.to_vec();
    if let Some(tx_type) = receipt.transaction_type {
        if tx_type.as_u32() > 0 {
            rlp = [vec![tx_type.as_u32() as u8], rlp].concat();
        }
    }
    rlp
}

async fn get_receipt_query(
    receipt_pf_max_depth: usize,
    receipts: Vec<TransactionReceipt>, // all receipts in the block
    tx_idx: usize,
    receipts_root: H256,
    max_data_byte_len: usize,
    max_log_num: usize,
    topic_num_bounds: (usize, usize),
) -> EthReceiptInput {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());
    let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
    let num_rcs = receipts.len();
    let mut vals_cache = Vec::new();
    for (idx, receipt) in receipts.into_iter().enumerate() {
        let mut rc_key = rlp::encode(&from_hex(&format!("{idx:x}"))).to_vec();
        if idx == 0 {
            rc_key = vec![0x80];
        }
        let rc_rlp = rlp_bytes(receipt);
        trie.insert(rc_key, rc_rlp.clone()).unwrap();
        vals_cache.push(rc_rlp);
    }
    let root = trie.root().unwrap();
    trie = PatriciaTrie::from(Arc::clone(&memdb), Arc::clone(&hasher), &root).unwrap();
    let root = trie.root().unwrap();
    assert!(root == receipts_root.as_bytes().to_vec());

    let mut rc_key = rlp::encode(&from_hex(&format!("{tx_idx:x}"))).to_vec();
    if tx_idx == 0 {
        rc_key = vec![0x80];
    }
    assert!(tx_idx < num_rcs, "Invalid transaction index");
    let rc_rlp = vals_cache[tx_idx].clone();
    let proof = MPTInput {
        path: (&rc_key).into(),
        value: rc_rlp,
        root_hash: receipts_root,
        proof: trie.get_proof(&rc_key).unwrap(),
        value_max_byte_len: rc_calc_max_val_len(max_data_byte_len, max_log_num, topic_num_bounds),
        max_depth: receipt_pf_max_depth,
        slot_is_empty: false,
        max_key_byte_len: 3,
        key_byte_len: Some(rc_key.len()),
    };
    EthReceiptInput { idx: tx_idx, proof }
}

pub fn get_full_storage_queries<P: JsonRpcClient>(
    provider: &Provider<P>,
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

pub fn get_block_transaction_input<P: JsonRpcClient>(
    provider: &Provider<P>,
    idxs: Vec<usize>,
    block_number: u32,
    transaction_pf_max_depth: usize,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
    constrain_len: bool,
) -> EthBlockTransactionInput {
    let rt = Runtime::new().unwrap();
    let block = rt
        .block_on(provider.get_block_with_txs(block_number as u64))
        .unwrap()
        .unwrap_or_else(|| panic!("Block {block_number} not found"));
    let block2 = rt
        .block_on(provider.get_block(block_number as u64))
        .unwrap()
        .unwrap_or_else(|| panic!("Block {block_number} not found"));

    for i in 0..block.transactions.len() {
        assert_eq!(block.transactions[i].hash(), block2.transactions[i]);
    }

    let block_hash = block.hash.unwrap();
    let block_header = get_block_rlp_tx(&block);

    let (tx_input, len_proof) = rt.block_on(get_transaction_query(
        transaction_pf_max_depth,
        block.clone().transactions,
        idxs,
        block.transactions_root,
        max_data_byte_len,
        max_access_list_len,
        enable_types,
        constrain_len,
    ));
    // println!("{block_header:?}");
    // println!("{tx_input:?}");
    EthBlockTransactionInput {
        block,
        block_number,
        block_hash,
        block_header,
        txs: tx_input,
        constrain_len,
        len_proof,
    }
}

pub fn get_block_transaction_len<P: JsonRpcClient>(
    provider: &Provider<P>,
    block_number: u32,
) -> usize {
    let rt = Runtime::new().unwrap();
    let block2 = rt
        .block_on(provider.get_block(block_number as u64))
        .unwrap()
        .unwrap_or_else(|| panic!("Block {block_number} not found"));
    block2.transactions.len()
}

pub fn get_block_transactions<P: JsonRpcClient>(
    provider: &Provider<P>,
    block_number: u32,
) -> Vec<Transaction> {
    let rt = Runtime::new().unwrap();
    let block2 = rt
        .block_on(provider.get_block_with_txs(block_number as u64))
        .unwrap()
        .unwrap_or_else(|| panic!("Block {block_number} not found"));
    block2.transactions
}

pub fn get_block_receipts<P: JsonRpcClient>(
    provider: &Provider<P>,
    block_number: u32,
) -> Vec<TransactionReceipt> {
    let rt = Runtime::new().unwrap();
    let block2 = rt
        .block_on(provider.get_block(block_number as u64))
        .unwrap()
        .unwrap_or_else(|| panic!("Block {block_number} not found"));
    let mut receipts = Vec::new();
    for transaction in block2.transactions {
        let receipt = rt
            .block_on(provider.get_transaction_receipt(transaction))
            .unwrap()
            .unwrap_or_else(|| panic!("Transaction {transaction} not found"));
        receipts.push(receipt);
    }
    receipts
}

pub fn get_block_access_list_num<P: JsonRpcClient>(
    provider: &Provider<P>,
    block_number: u32,
) -> usize {
    let rt = Runtime::new().unwrap();
    let block2 = rt
        .block_on(provider.get_block_with_txs(block_number as u64))
        .unwrap()
        .unwrap_or_else(|| panic!("Block {block_number} not found"));
    let mut cnt: usize = 0;
    for tx in block2.transactions {
        match tx.access_list {
            None => {}
            Some(al) => {
                cnt += !al.0.is_empty() as usize;
            }
        }
    }
    cnt
}

pub fn get_block_receipt_input<P: JsonRpcClient>(
    provider: &Provider<P>,
    tx_hash: H256,
    receipt_pf_max_depth: usize,
    max_data_byte_len: usize,
    max_log_num: usize,
    topic_num_bounds: (usize, usize),
) -> EthBlockReceiptInput {
    let rt = Runtime::new().unwrap();
    let tx = rt
        .block_on(provider.get_transaction(tx_hash))
        .unwrap()
        .unwrap_or_else(|| panic!("Transaction {tx_hash} not found"));
    let block_number = tx.block_number.unwrap().as_u32();
    let block = get_blocks(provider, [block_number as u64]).unwrap().pop().unwrap().unwrap();
    let block_hash = block.hash.unwrap();
    let block_header = get_block_rlp(&block);
    let receipts = get_block_receipts(provider, block_number);
    // requested receipt pf
    let receipt = rt.block_on(get_receipt_query(
        receipt_pf_max_depth,
        receipts,
        tx.transaction_index.unwrap().as_usize(),
        block.receipts_root,
        max_data_byte_len,
        max_log_num,
        topic_num_bounds,
    ));
    EthBlockReceiptInput { block_number, block_hash, block_header, receipt }
}

pub fn get_block_rlp_from_num<P: JsonRpcClient>(
    provider: &Provider<P>,
    block_number: u32,
) -> Vec<u8> {
    let rt = Runtime::new().unwrap();
    let block2 = rt
        .block_on(provider.get_block(block_number as u64))
        .unwrap()
        .unwrap_or_else(|| panic!("Block {block_number} not found"));
    get_block_rlp(&block2)
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

pub fn get_block_rlp_tx(block: &Block<Transaction>) -> Vec<u8> {
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

pub fn get_block_rlp_unrestricted(block: &Block<H256>) -> Vec<u8> {
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
pub fn get_blocks_input<P: JsonRpcClient>(
    provider: &Provider<P>,
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
    fn test_retry_provider() {
        let provider_uri = var("JSON_RPC_URL").expect("JSON_RPC_URL not found");
        let provider = Provider::new_client(&provider_uri, 10, 500)
            .expect("could not instantiate HTTP Provider");

        let rt = Runtime::new().unwrap();
        let block = rt.block_on(provider.get_block(17034973)).unwrap().unwrap();
        get_block_rlp(&block);
    }

    #[test]
    fn correct_root() {
        let block_number = (var("BLOCK_NUM").expect("INFURA_ID environmental variable not set"))
            .parse::<i32>()
            .unwrap();
        let infura_id = "10550e24777046d19ae0e4598a6eed53";
        let provider_url = format!("{MAINNET_PROVIDER_URL}{infura_id}");
        let provider = Provider::new_client(&provider_url, 10, 500)
            .expect("could not instantiate HTTP Provider");
        let rt = Runtime::new().unwrap();
        let block2 = rt
            .block_on(provider.get_block(block_number as u64))
            .unwrap()
            .unwrap_or_else(|| panic!("Block {block_number} not found"));
        let mut receipts = Vec::new();
        for transaction in block2.transactions {
            receipts.push(rt.block_on(provider.get_transaction_receipt(transaction)).unwrap())
        }
        let receipts_root = block2.receipts_root;
        let memdb = Arc::new(MemoryDB::new(true));
        let hasher = Arc::new(HasherKeccak::new());
        let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
        let num_rcs = receipts.len();
        let mut vals_cache = Vec::new();
        for idx in 0..num_rcs {
            let rc = receipts[idx].clone();
            match rc {
                None => {}
                Some(rc) => {
                    let mut rc_key =
                        rlp::encode(&from_hex(&format!("{idx:x}").to_string())).to_vec();
                    if idx == 0 {
                        rc_key = vec![0x80];
                    }
                    let rc_rlp = rlp_bytes(rc);
                    println!("RC_RLP: {rc_rlp:02x?}");
                    trie.insert(rc_key.clone(), rc_rlp.clone()).unwrap();
                    vals_cache.push(rc_rlp);
                }
            }
        }
        let root = trie.root().unwrap();
        trie = PatriciaTrie::from(Arc::clone(&memdb), Arc::clone(&hasher), &root).unwrap();
        let root = trie.root().unwrap();
        assert!(root == receipts_root.as_bytes().to_vec());
    }
}

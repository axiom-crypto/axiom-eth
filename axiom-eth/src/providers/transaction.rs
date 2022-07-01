use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, bail};
use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use ethers_core::types::{Block, Bytes, Transaction, H256, U128, U64};
use ethers_providers::{JsonRpcClient, Middleware, Provider};
use hasher::HasherKeccak;
use rlp::RlpStream;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use crate::providers::from_hex;
#[cfg(test)]
use crate::{
    mpt::MPTInput,
    transaction::{
        calc_max_val_len as tx_calc_max_val_len, EthBlockTransactionsInput, EthTransactionLenProof,
        EthTransactionProof,
    },
};

// ========== Raw Transaction RLP computations =============
// These are not yet implemented in alloy, and ethers_core does not support EIP-4844 transactions, so we keep a custom implementation here.

/// The new fields in a EIP 4844 blob transaction.
/// This object is meant to be transmuted from the `other` field in [`Transaction`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobTransactionFields {
    /// Configured max fee per blob gas for eip-4844 transactions
    pub max_fee_per_blob_gas: U128,
    /// Contains the blob hashes for eip-4844 transactions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blob_versioned_hashes: Vec<H256>,
}

/// Computes the RLP encoding, in bytes, of a raw transaction.
/// Updates `ethers_core` to support EIP-4844 transactions.
pub fn get_transaction_rlp(transaction: &Transaction) -> anyhow::Result<Bytes> {
    match transaction.transaction_type {
        // EIP-4844 blob transaction
        Some(x) if x == U64::from(3) => {
            let other = serde_json::to_value(&transaction.other)?;
            let blob_fields: BlobTransactionFields = serde_json::from_value(other)?;
            let mut rlp = RlpStream::new();
            rlp.begin_unbounded_list();
            let chain_id = transaction.chain_id.ok_or(anyhow!("Eip4844 tx missing chainId"))?;
            let max_priority_fee_per_gas = transaction
                .max_priority_fee_per_gas
                .ok_or(anyhow!("Eip4844 tx missing maxPriorityFeePerGas"))?;
            let max_fee_per_gas =
                transaction.max_fee_per_gas.ok_or(anyhow!("Eip4844 tx missing maxFeePerGas"))?;
            let to = transaction.to.ok_or(anyhow!("Eip4844 tx `to` MUST NOT be nil"))?;
            rlp.append(&chain_id);
            rlp.append(&transaction.nonce);
            rlp.append(&max_priority_fee_per_gas);
            rlp.append(&max_fee_per_gas);
            rlp.append(&transaction.gas);
            rlp.append(&to);
            rlp.append(&transaction.value);
            rlp.append(&transaction.input.as_ref());
            rlp_opt_list(&mut rlp, &transaction.access_list);
            rlp.append(&blob_fields.max_fee_per_blob_gas);
            rlp.append_list(&blob_fields.blob_versioned_hashes);
            rlp.append(&normalize_v(transaction.v.as_u64(), chain_id.as_u64()));
            rlp.append(&transaction.r);
            rlp.append(&transaction.s);
            rlp.finalize_unbounded_list();
            let rlp_bytes: Bytes = rlp.out().freeze().into();
            let mut encoded = vec![];
            encoded.extend_from_slice(&[0x3]);
            encoded.extend_from_slice(rlp_bytes.as_ref());
            Ok(encoded.into())
        }
        // Legacy, EIP-2718, or EIP-155 transactions are handled by ethers_core
        // So are Optimism Deposited Transactions
        _ => Ok(transaction.rlp()),
    }
}

// Copied from https://github.com/gakonst/ethers-rs/blob/5394d899adca736a602e316e6f0c06fdb5aa64b9/ethers-core/src/types/transaction/mod.rs#L22
/// RLP encode a value if it exists or else encode an empty string.
pub fn rlp_opt<T: rlp::Encodable>(rlp: &mut rlp::RlpStream, opt: &Option<T>) {
    if let Some(inner) = opt {
        rlp.append(inner);
    } else {
        rlp.append(&"");
    }
}

/// RLP encode a value if it exists or else encode an empty list.
pub fn rlp_opt_list<T: rlp::Encodable>(rlp: &mut rlp::RlpStream, opt: &Option<T>) {
    if let Some(inner) = opt {
        rlp.append(inner);
    } else {
        // Choice of `u8` type here is arbitrary as all empty lists are encoded the same.
        rlp.append_list::<u8, u8>(&[]);
    }
}

/// normalizes the signature back to 0/1
pub fn normalize_v(v: u64, chain_id: u64) -> u64 {
    if v > 1 {
        v - chain_id * 2 - 35
    } else {
        v
    }
}

// ========================= Transactions Trie Construction =========================
pub struct BlockTransactionsDb {
    pub trie: PatriciaTrie<MemoryDB, HasherKeccak>,
    pub root: H256,
    pub tx_rlps: Vec<Vec<u8>>,
}

impl BlockTransactionsDb {
    pub fn new(
        trie: PatriciaTrie<MemoryDB, HasherKeccak>,
        root: H256,
        tx_rlps: Vec<Vec<u8>>,
    ) -> Self {
        Self { trie, root, tx_rlps }
    }
}

// ===== Block with Transactions =====
/// A block with all transactions. We require the transactionsRoot to be provided for a safety check.
/// Deserialization should still work on an object with extra fields.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockWithTransactions {
    /// Block number
    pub number: U64,
    /// Transactions root hash
    pub transactions_root: H256,
    /// All transactions in the block
    pub transactions: Vec<Transaction>,
}

impl TryFrom<Block<Transaction>> for BlockWithTransactions {
    type Error = &'static str;
    fn try_from(block: Block<Transaction>) -> Result<Self, Self::Error> {
        Ok(Self {
            number: block.number.ok_or("Block not in chain")?,
            transactions_root: block.transactions_root,
            transactions: block.transactions,
        })
    }
}

/// For each block with all raw transactions, constructs the Merkle Patricia trie and returns a map from block number to the trie as well as flat vector of transactions.
pub fn construct_tx_tries_from_full_blocks(
    blocks: Vec<BlockWithTransactions>,
) -> anyhow::Result<HashMap<u64, BlockTransactionsDb>> {
    let mut tries = HashMap::new();
    for block in blocks {
        let mut trie =
            PatriciaTrie::new(Arc::new(MemoryDB::new(true)), Arc::new(HasherKeccak::new()));
        let mut tx_rlps = Vec::with_capacity(block.transactions.len());
        for (idx, tx) in block.transactions.into_iter().enumerate() {
            let tx_key = get_tx_key_from_index(idx);
            let tx_rlp = get_transaction_rlp(&tx)?.to_vec();
            tx_rlps.push(tx_rlp.clone());
            trie.insert(tx_key, tx_rlp)?;
        }
        // safety check:
        let root = trie.root()?;
        if root != block.transactions_root.as_bytes() {
            bail!("Transactions trie incorrectly constructed");
        }
        let root = block.transactions_root;
        tries.insert(block.number.as_u64(), BlockTransactionsDb::new(trie, root, tx_rlps));
    }
    Ok(tries)
}

pub fn get_tx_key_from_index(idx: usize) -> Vec<u8> {
    let mut tx_key = rlp::encode(&from_hex(&format!("{idx:x}"))).to_vec();
    if idx == 0 {
        tx_key = vec![0x80];
    }
    tx_key
}

// This function only for testing use
#[cfg(test)]
/// Creates transaction proof by reconstructing the transaction MPTrie.
/// `transactions` should be all transactions in the block
async fn get_transaction_query(
    transaction_pf_max_depth: usize,
    transactions: Vec<Transaction>,
    idxs: Vec<usize>,
    transactions_root: H256,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
    constrain_len: bool,
) -> (Vec<EthTransactionProof>, Option<EthTransactionLenProof>) {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());
    let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
    let num_txs = transactions.len();
    let mut pfs = Vec::new();
    let mut vals_cache = Vec::new();
    #[allow(clippy::needless_range_loop)]
    for idx in 0..num_txs {
        let tx = transactions[idx].clone();
        let mut tx_key = rlp::encode(&from_hex(&format!("{idx:x}").to_string())).to_vec();
        if idx == 0 {
            tx_key = vec![0x80];
        }
        let tx_rlp = get_transaction_rlp(&tx).unwrap().to_vec();
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
        let proof = MPTInput {
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
            slot_is_empty: idx >= num_txs,
            max_key_byte_len: 3,
            key_byte_len: Some(tx_key.len()),
        };
        pfs.push(EthTransactionProof { tx_index: idx, proof });
    }
    let pf0 = if num_txs > 0 {
        let mut tx_key = rlp::encode(&from_hex(&format!("{:x}", num_txs - 1))).to_vec();
        if num_txs == 1 {
            tx_key = vec![0x80];
        }
        let tx_rlp = vals_cache[num_txs - 1].clone();
        EthTransactionProof {
            tx_index: num_txs - 1,
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
            tx_index: num_txs + 1,
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
        tx_index: num_txs,
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
    (pfs, len_proof)
}

#[cfg(test)]
pub fn get_block_transaction_input<P: JsonRpcClient>(
    provider: &Provider<P>,
    idxs: Vec<usize>,
    block_number: u32,
    transaction_pf_max_depth: usize,
    max_data_byte_len: usize,
    max_access_list_len: usize,
    enable_types: [bool; 3],
    constrain_len: bool,
) -> EthBlockTransactionsInput {
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
    let block_header = super::block::get_block_rlp(&block);

    let (tx_proofs, len_proof) = rt.block_on(get_transaction_query(
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
    EthBlockTransactionsInput {
        block,
        block_number,
        block_hash,
        block_header,
        tx_proofs,
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

#[cfg(test)]
mod data_analysis {
    use std::{fs::File, io::Write};

    use ethers_core::types::Chain;
    use ethers_providers::Middleware;
    use rlp::RlpStream;

    use crate::providers::{
        setup_provider,
        transaction::{construct_tx_tries_from_full_blocks, BlockWithTransactions},
    };

    use super::{get_block_access_list_num, get_block_transaction_len, get_block_transactions};

    // Tests some fixed blocks as well as the 10 latest blocks
    #[tokio::test]
    async fn test_reconstruct_tx_trie_mainnet() -> anyhow::Result<()> {
        let provider = setup_provider(Chain::Mainnet);
        let latest_block = provider.get_block_number().await.unwrap().as_u64();
        let mut block_nums =
            vec![500_000, 5_000_050, 5_000_051, 17_034_973, 19_426_587, 19_426_589];
        for i in 0..10 {
            block_nums.push(latest_block - i);
        }
        let mut full_blocks = Vec::new();
        for block_num in block_nums {
            let block = provider.get_block_with_txs(block_num).await?.unwrap();
            let block: BlockWithTransactions =
                serde_json::from_value(serde_json::to_value(block)?)?;
            full_blocks.push(block);
        }
        // Will panic if any tx root does not match trie root:
        construct_tx_tries_from_full_blocks(full_blocks)?;
        Ok(())
    }

    // Tests some fixed blocks as well as the 10 latest blocks
    // Tests OP stack deposit transactions
    #[tokio::test]
    async fn test_reconstruct_tx_trie_base() -> anyhow::Result<()> {
        let provider = setup_provider(Chain::Base);
        let latest_block = provider.get_block_number().await.unwrap().as_u64();
        let mut block_nums = vec![10, 100_000, 5_000_050, 8_000_000, 11_864_572];
        for i in 0..10 {
            block_nums.push(latest_block - i);
        }
        let mut full_blocks = Vec::new();
        dbg!(&block_nums);
        for block_num in block_nums {
            let block = provider.get_block_with_txs(block_num).await?.unwrap();
            let block: BlockWithTransactions =
                serde_json::from_value(serde_json::to_value(block)?)?;
            full_blocks.push(block);
        }
        // Will panic if any tx root does not match trie root:
        construct_tx_tries_from_full_blocks(full_blocks)?;
        Ok(())
    }

    #[test]
    #[ignore]
    pub fn find_good_block256() {
        let provider = setup_provider(Chain::Mainnet);
        for block_number in 5000000..6000000 {
            let num_tx = get_block_transaction_len(&provider, block_number.try_into().unwrap());
            if num_tx > 256 {
                println!("Desired Block: {block_number:?}");
            }
        }
    }

    #[test]
    #[ignore]
    pub fn find_access_lists() {
        let provider = setup_provider(Chain::Mainnet);
        let mut trend = Vec::new();

        let mut data_file = File::create("data.txt").expect("creation failed");
        for i in 0..100 {
            let cnt = get_block_access_list_num(&provider, 17578525 - i);
            trend.push((17578525 - i, cnt));
            data_file.write_all((cnt.to_string() + "\n").as_bytes()).expect("write failed");
        }
    }

    #[test]
    #[ignore]
    pub fn find_transaction_lens() {
        let provider = setup_provider(Chain::Mainnet);
        let mut trend = Vec::new();

        let mut data_file = File::create("data.txt").expect("creation failed");
        for i in 0..100 {
            let transactions = get_block_transactions(&provider, 17578525 - i);
            for (j, transaction) in transactions.into_iter().enumerate() {
                trend.push((17578525 - i, transaction.input.len()));
                let _len = match transaction.access_list {
                    Some(a_list) => {
                        let mut s = RlpStream::new();
                        s.append(&a_list);
                        let rlp_bytes: Vec<u8> = s.out().freeze().into();
                        rlp_bytes.len()
                    }
                    None => 0,
                };
                let len = transaction.input.len();
                data_file
                    .write_all(
                        (len.to_string()
                            + ", "
                            + &j.to_string()
                            + ", "
                            + &(17578525 - i).to_string()
                            + ", "
                            + "\n")
                            .as_bytes(),
                    )
                    .expect("write failed");
            }
        }
    }
}

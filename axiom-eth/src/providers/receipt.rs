use std::sync::Arc;

use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use ethers_core::types::{TransactionReceipt, H256};
use ethers_providers::{JsonRpcClient, Middleware, Provider};
use hasher::HasherKeccak;
use rlp::RlpStream;
use tokio::runtime::Runtime;

use crate::receipt::{calc_max_val_len as rc_calc_max_val_len, EthBlockReceiptInput};
use crate::{mpt::MPTInput, providers::from_hex, receipt::EthReceiptInput};

use super::block::{get_block_rlp, get_blocks};

/// This is a fix to <https://github.com/gakonst/ethers-rs/issues/2500>
pub fn rlp_bytes(receipt: TransactionReceipt) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use std::{env::var, sync::Arc};

    use cita_trie::{MemoryDB, PatriciaTrie, Trie};
    use ethers_core::types::Chain;
    use ethers_providers::Middleware;
    use hasher::HasherKeccak;
    use tokio::runtime::Runtime;

    use crate::providers::{from_hex, receipt::rlp_bytes, setup_provider};

    #[test]
    fn correct_root() {
        let block_number = (var("BLOCK_NUM").expect("BLOCK_NUM environmental variable not set"))
            .parse::<i32>()
            .unwrap();
        let provider = setup_provider(Chain::Mainnet);
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
        #[allow(clippy::needless_range_loop)]
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

#[cfg(test)]
mod data_analysis {
    use std::{fs::File, io::Write};

    use ethers_core::types::Chain;

    use crate::providers::setup_provider;

    use super::*;
    #[test]
    #[ignore]
    pub fn find_receipt_lens() -> Result<(), Box<dyn std::error::Error>> {
        let provider = setup_provider(Chain::Mainnet);

        let mut data_file = File::create("data.txt").expect("creation failed");
        for i in 0..100 {
            let receipts = get_block_receipts(&provider, 17578525 - i);
            for (j, receipt) in receipts.into_iter().enumerate() {
                let _len = {
                    let mut s = RlpStream::new();
                    s.append_list(&receipt.logs);
                    let rlp_bytes: Vec<u8> = s.out().freeze().into();
                    rlp_bytes.len()
                };
                //let len = transaction.input.len();
                //let len = receipts[j].logs.len();
                for i in 0..receipt.logs.len() {
                    let len = receipt.logs[i].data.len();
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
        Ok(())
    }
}

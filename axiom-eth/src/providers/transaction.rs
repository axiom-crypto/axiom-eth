use std::sync::Arc;

use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use ethers_core::types::{Transaction, H256};
use ethers_providers::{JsonRpcClient, Middleware, Provider};
use hasher::HasherKeccak;
use tokio::runtime::Runtime;

use crate::{
    mpt::MPTInput,
    providers::from_hex,
    transaction::{
        calc_max_val_len as tx_calc_max_val_len, EthBlockTransactionsInput, EthTransactionLenProof,
        EthTransactionProof,
    },
};

use super::block::get_block_rlp;

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
    let block_header = get_block_rlp(&block);

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
    use rlp::RlpStream;

    use crate::providers::setup_provider;

    use super::{get_block_access_list_num, get_block_transaction_len, get_block_transactions};

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

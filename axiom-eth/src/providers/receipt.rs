use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use cita_trie::{MemoryDB, PatriciaTrie, Trie};
use ethers_core::types::{Address, Bloom, Bytes, Log, OtherFields, H256, U128, U256, U64};
use ethers_providers::{JsonRpcClient, Middleware, Provider};
use futures::future::join_all;
use hasher::HasherKeccak;
use rlp::RlpStream;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use tokio::runtime::Runtime;

#[cfg(test)]
use crate::{
    mpt::MPTInput,
    providers::block::{get_block_rlp, get_blocks},
    providers::from_hex,
    receipt::EthReceiptInput,
    receipt::{calc_max_val_len as rc_calc_max_val_len, EthBlockReceiptInput},
};

use super::transaction::get_tx_key_from_index;

// Issue: https://github.com/gakonst/ethers-rs/issues/2768
// Copying from: https://github.com/alloy-rs/alloy/blob/410850b305a28297483d819b669b04ba31796359/crates/rpc-types/src/eth/transaction/receipt.rs#L8
/// "Receipt" of an executed transaction: details of its execution.
/// Transaction receipt
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    /// Transaction Hash.
    pub transaction_hash: Option<H256>,
    /// Index within the block.
    pub transaction_index: U64,
    /// Hash of the block this transaction was included within.
    pub block_hash: Option<H256>,
    /// Number of the block this transaction was included within.
    pub block_number: Option<U64>,
    /// Address of the sender
    pub from: Address,
    /// Address of the receiver. None when its a contract creation transaction.
    pub to: Option<Address>,
    /// Cumulative gas used within the block after this was executed.
    pub cumulative_gas_used: U256,
    /// Gas used by this transaction alone.
    ///
    /// Gas used is `None` if the the client is running in light client mode.
    pub gas_used: Option<U256>,
    /// Contract address created, or None if not a deployment.
    pub contract_address: Option<Address>,
    /// Logs emitted by this transaction.
    pub logs: Vec<Log>,
    /// Status: either 1 (success) or 0 (failure). Only present after activation of EIP-658
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<U64>,
    /// State root. Only present before activation of [EIP-658](https://eips.ethereum.org/EIPS/eip-658)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<H256>,
    /// Logs bloom
    pub logs_bloom: Bloom,
    /// EIP-2718 Transaction type, Some(1) for AccessList transaction, None for Legacy
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<U64>,
    /// The price paid post-execution by the transaction (i.e. base fee + priority fee). Both
    /// fields in 1559-style transactions are maximums (max fee + max priority fee), the amount
    /// that's actually paid by users can only be determined post-execution
    #[serde(rename = "effectiveGasPrice", default, skip_serializing_if = "Option::is_none")]
    pub effective_gas_price: Option<U256>,

    // Note: blob_gas_used and blob_gas_price are not part of the EIP-2718 ReceiptPayload
    /// Blob gas used by the eip-4844 transaction
    ///
    /// This is None for non eip-4844 transactions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_gas_used: Option<U128>,
    /// The price paid by the eip-4844 transaction per blob gas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_gas_price: Option<U128>,

    /// Arbitrary extra fields. Contains fields specific to, e.g., L2s.
    #[serde(flatten)]
    pub other: OtherFields,
}

// Copied from https://github.com/alloy-rs/alloy/blob/410850b305a28297483d819b669b04ba31796359/crates/rpc-types/src/eth/transaction/optimism.rs#L25
/// Additional fields for Optimism transaction receipts
#[derive(Clone, Copy, Default, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OptimismTransactionReceiptFields {
    /// Deposit nonce for deposit transactions post-regolith
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deposit_nonce: Option<U64>,
    /// Deposit receipt version for deposit transactions post-canyon
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deposit_receipt_version: Option<U64>,
    /// L1 fee for the transaction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l1_fee: Option<U256>,
    /// L1 fee scalar for the transaction
    #[serde(default, skip_serializing_if = "Option::is_none", with = "l1_fee_scalar_serde")]
    pub l1_fee_scalar: Option<f64>,
    /// L1 gas price for the transaction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l1_gas_price: Option<U256>,
    /// L1 gas used for the transaction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l1_gas_used: Option<U256>,
}

/// Serialize/Deserialize l1FeeScalar to/from string
mod l1_fee_scalar_serde {
    use serde::{de, Deserialize};

    pub(super) fn serialize<S>(value: &Option<f64>, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if let Some(v) = value {
            return s.serialize_str(&v.to_string());
        }
        s.serialize_none()
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        if let Some(s) = s {
            return Ok(Some(s.parse::<f64>().map_err(de::Error::custom)?));
        }

        Ok(None)
    }
}

/// This is a fix to <https://github.com/gakonst/ethers-rs/issues/2500>.
/// Also fixes the OP stack deposit receipt RLP encoding.
/// `reth` reference: https://github.com/paradigmxyz/reth/blob/4e1c56f8d0baf7282b8ceb5ff8c93da66961ca2a/crates/primitives/src/receipt.rs#L486
pub fn get_receipt_rlp(receipt: &TransactionReceipt) -> anyhow::Result<Bytes> {
    let mut s = RlpStream::new();
    s.begin_unbounded_list();
    if let Some(post_state) = receipt.root {
        s.append(&post_state);
    } else {
        s.append(&receipt.status.ok_or(anyhow!("No post-state or status in receipt"))?);
    }
    s.append(&receipt.cumulative_gas_used);
    s.append(&receipt.logs_bloom);
    s.append_list(&receipt.logs);

    // OP stack deposit transaction
    // https://specs.optimism.io/protocol/deposits.html#deposit-receipt
    if receipt.transaction_type == Some(U64::from(0x7E)) {
        let op_fields: OptimismTransactionReceiptFields =
            serde_json::from_value(serde_json::to_value(&receipt.other)?)?;
        // https://github.com/paradigmxyz/reth/blob/4e1c56f8d0baf7282b8ceb5ff8c93da66961ca2a/crates/primitives/src/receipt.rs#L40
        if let Some(deposit_receipt_version) = op_fields.deposit_receipt_version {
            // RPC providers seem to provide depositNonce even before Canyon, so we use receipt version as indicator
            let deposit_nonce = op_fields
                .deposit_nonce
                .ok_or(anyhow!("Canyon deposit receipt without depositNonce"))?;
            s.append(&deposit_nonce);
            // This is denoted as "depositReceiptVersion" in RPC responses, not "depositNonceVersion" like in the docs
            s.append(&deposit_receipt_version);
        }
    }

    s.finalize_unbounded_list();
    let rlp_bytes: Bytes = s.out().freeze().into();
    let mut encoded = vec![];
    if let Some(tx_type) = receipt.transaction_type {
        let tx_type = u8::try_from(tx_type.as_u64())
            .map_err(|_| anyhow!("Transaction type is not a byte"))?;
        if tx_type > 0 {
            encoded.extend_from_slice(&[tx_type]);
        }
    }
    encoded.extend_from_slice(rlp_bytes.as_ref());
    Ok(encoded.into())
}

// ========================= Receipts Trie Construction =========================
pub struct BlockReceiptsDb {
    pub trie: PatriciaTrie<MemoryDB, HasherKeccak>,
    pub root: H256,
    pub rc_rlps: Vec<Vec<u8>>,
}

impl BlockReceiptsDb {
    pub fn new(
        trie: PatriciaTrie<MemoryDB, HasherKeccak>,
        root: H256,
        rc_rlps: Vec<Vec<u8>>,
    ) -> Self {
        Self { trie, root, rc_rlps }
    }
}

// ===== Block with Receipts =====
/// A block with all receipts. We require the receiptsRoot to be provided for a safety check.
/// Deserialization should still work on an object with extra fields.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockWithReceipts {
    /// Block number
    pub number: U64,
    /// Receipts root hash
    pub receipts_root: H256,
    /// All receipts in the block
    pub receipts: Vec<TransactionReceipt>,
}

pub fn construct_rc_tries_from_full_blocks(
    blocks: Vec<BlockWithReceipts>,
) -> anyhow::Result<HashMap<u64, BlockReceiptsDb>> {
    let mut tries = HashMap::new();
    for block in blocks {
        let mut trie =
            PatriciaTrie::new(Arc::new(MemoryDB::new(true)), Arc::new(HasherKeccak::new()));
        let mut rc_rlps = Vec::with_capacity(block.receipts.len());
        for (idx, rc) in block.receipts.into_iter().enumerate() {
            let tx_key = get_tx_key_from_index(idx);
            let rc_rlp = get_receipt_rlp(&rc)?.to_vec();
            rc_rlps.push(rc_rlp.clone());
            trie.insert(tx_key, rc_rlp)?;
        }
        // safety check:
        let root = trie.root()?;
        if root != block.receipts_root.as_bytes() {
            anyhow::bail!("Transactions trie incorrectly constructed for block {}", block.number);
        }
        let root = block.receipts_root;
        tries.insert(block.number.as_u64(), BlockReceiptsDb::new(trie, root, rc_rlps));
    }
    Ok(tries)
}

// This function only for testing use
#[cfg(test)]
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
        let rc_rlp = get_receipt_rlp(&receipt).unwrap().to_vec();
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

/// Default is 3 retries for each receipt.
pub async fn get_block_with_receipts<P: JsonRpcClient>(
    provider: &Provider<P>,
    block_number: u64,
    retries: Option<usize>,
) -> anyhow::Result<BlockWithReceipts> {
    let default_retries = 3;
    let block = provider.get_block(block_number).await?.ok_or(anyhow!("Failed to get block"))?;
    let receipts = join_all(block.transactions.iter().map(|&tx_hash| {
        let mut retries = retries.unwrap_or(default_retries);
        async move {
            loop {
                let receipt = provider.request("eth_getTransactionReceipt", [tx_hash]).await;
                match receipt {
                    Ok(Some(receipt)) => return Ok(receipt),
                    Ok(None) => {
                        if retries == 0 {
                            return Err(anyhow!("Receipt not found after {}", retries));
                        }
                        retries -= 1;
                    }
                    Err(e) => {
                        if retries == 0 {
                            return Err(e.into());
                        }
                        retries -= 1;
                    }
                }
            }
        }
    }))
    .await
    .into_iter()
    .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(BlockWithReceipts {
        number: block_number.into(),
        receipts_root: block.receipts_root,
        receipts,
    })
}

#[cfg(test)]
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
    let block_number = tx.block_number.unwrap().as_u64();
    let block = get_blocks(provider, [block_number]).unwrap().pop().unwrap().unwrap();
    let block_hash = block.hash.unwrap();
    let block_header = get_block_rlp(&block);
    let receipts =
        rt.block_on(get_block_with_receipts(provider, block_number, None)).unwrap().receipts;
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
    EthBlockReceiptInput { block_number: block_number as u32, block_hash, block_header, receipt }
}

#[cfg(test)]
mod tests {
    use ethers_core::types::Chain;
    use ethers_providers::Middleware;

    use crate::providers::{
        receipt::{
            construct_rc_tries_from_full_blocks, get_block_with_receipts, BlockWithReceipts,
        },
        setup_provider,
    };

    // Tests some fixed blocks as well as the 10 latest blocks
    #[tokio::test]
    async fn test_reconstruct_receipt_trie_mainnet() -> anyhow::Result<()> {
        let provider = setup_provider(Chain::Mainnet);
        let latest_block = provider.get_block_number().await.unwrap().as_u64();
        let mut block_nums = vec![
            50_000, 500_000, 5_000_050, 5_000_051, 17_000_000, 17_034_973, 19_426_587, 19_426_589,
        ];
        for i in 0..10 {
            block_nums.push(latest_block - i);
        }
        let mut full_blocks = Vec::new();
        for block_num in block_nums {
            let block = get_block_with_receipts(&provider, block_num, None).await?;
            let block: BlockWithReceipts = serde_json::from_value(serde_json::to_value(block)?)?;
            full_blocks.push(block);
        }
        // Will panic if any tx root does not match trie root:
        construct_rc_tries_from_full_blocks(full_blocks)?;
        Ok(())
    }

    // Tests some fixed blocks as well as the 10 latest blocks
    // Tests OP stack deposit transactions
    #[tokio::test]
    async fn test_reconstruct_receipt_trie_base() -> anyhow::Result<()> {
        let provider = setup_provider(Chain::Base);
        let latest_block = provider.get_block_number().await.unwrap().as_u64();
        let mut block_nums = vec![10, 100_000, 5_000_050, 8_000_000, 8578617, 11_864_572];
        for i in 0..10 {
            block_nums.push(latest_block - i);
        }
        let mut full_blocks = Vec::new();
        for block_num in block_nums {
            let block = get_block_with_receipts(&provider, block_num, None).await?;
            let block: BlockWithReceipts = serde_json::from_value(serde_json::to_value(block)?)?;
            full_blocks.push(block);
        }
        // Will panic if any tx root does not match trie root:
        construct_rc_tries_from_full_blocks(full_blocks)?;
        Ok(())
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
        let rt = Runtime::new().unwrap();
        let provider = setup_provider(Chain::Mainnet);

        let mut data_file = File::create("data.txt").expect("creation failed");
        for i in 0..100 {
            let receipts = rt
                .block_on(get_block_with_receipts(&provider, 17578525 - i, None))
                .unwrap()
                .receipts;
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

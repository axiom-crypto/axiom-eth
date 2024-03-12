use ethers_core::{
    types::{Block, H256, U64},
    utils::keccak256,
};
use ethers_providers::{JsonRpcClient, Middleware, Provider, ProviderError};
use futures::future::join_all;
use rlp::RlpStream;
use tokio::runtime::Runtime;

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

pub fn get_block_rlp<TX>(block: &Block<TX>) -> Vec<u8> {
    let base_fee = block.base_fee_per_gas;
    let withdrawals_root: Option<H256> = block.withdrawals_root;
    // EIP-4844:
    let other = &block.other;
    let mut blob_gas_used = other.get("blobGasUsed"); // EIP-4844 spec
    if blob_gas_used.is_none() {
        blob_gas_used = other.get("dataGasUsed"); // EIP-4788 spec
    }
    let blob_gas_used: Option<U64> =
        blob_gas_used.map(|v| serde_json::from_value(v.clone()).unwrap());
    let mut excess_blob_gas = other.get("excessBlobGas"); // EIP-4844 spec
    if excess_blob_gas.is_none() {
        excess_blob_gas = other.get("excessDataGas"); // EIP-4788 spec
    }
    let excess_blob_gas: Option<U64> =
        excess_blob_gas.map(|v| serde_json::from_value(v.clone()).unwrap());
    // EIP-4788:
    let parent_beacon_block_root: Option<H256> =
        other.get("parentBeaconBlockRoot").map(|v| serde_json::from_value(v.clone()).unwrap());

    let mut rlp_len = 15;
    for opt in [
        base_fee.is_some(),
        withdrawals_root.is_some(),
        blob_gas_used.is_some(),
        excess_blob_gas.is_some(),
        parent_beacon_block_root.is_some(),
    ] {
        rlp_len += opt as usize;
    }
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
    blob_gas_used.map(|blob_gas_used| rlp.append(&blob_gas_used));
    excess_blob_gas.map(|excess_blob_gas| rlp.append(&excess_blob_gas));
    parent_beacon_block_root.map(|parent_beacon_block_root| rlp.append(&parent_beacon_block_root));
    let encoding: Vec<u8> = rlp.out().into();
    assert_eq!(keccak256(&encoding), block.hash.unwrap().0);
    encoding
}

/// returns vector of RLP bytes of each block in [start_block_number, start_block_number + num_blocks)
pub fn get_blocks_input<P: JsonRpcClient>(
    provider: &Provider<P>,
    start_block_number: u32,
    num_blocks: u32,
) -> Vec<Vec<u8>> {
    let blocks =
        get_blocks(provider, start_block_number as u64..(start_block_number + num_blocks) as u64)
            .unwrap_or_else(|e| panic!("get_blocks JSON-RPC call failed: {e}"));
    blocks
        .into_iter()
        .map(|block| {
            let block = block.expect("block not found");
            get_block_rlp(&block)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ethers_core::types::Chain;
    use ethers_providers::Middleware;

    use crate::providers::setup_provider;

    use super::*;

    #[test]
    fn test_retry_provider() {
        let provider = setup_provider(Chain::Mainnet);

        let rt = Runtime::new().unwrap();
        for block_num in [5000050, 5000051, 17034973] {
            let block = rt.block_on(provider.get_block(block_num)).unwrap().unwrap();
            get_block_rlp(&block);
        }
    }

    #[test]
    fn test_retry_provider_sepolia() {
        let provider = setup_provider(Chain::Sepolia);

        let rt = Runtime::new().unwrap();
        let latest = rt.block_on(provider.get_block_number()).unwrap();
        for block_num in [0, 5000050, 5187810, 5187814, latest.as_u64()] {
            let block = rt.block_on(provider.get_block(block_num)).unwrap().unwrap();
            get_block_rlp(&block);
        }
    }
}

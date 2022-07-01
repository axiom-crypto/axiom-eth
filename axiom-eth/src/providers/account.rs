use ethers_core::types::{Address, EIP1186ProofResponse};
use ethers_providers::{JsonRpcClient, Middleware, Provider};
use futures::future::join_all;
use rlp::RlpStream;
use tokio::runtime::Runtime;

use crate::storage::{circuit::EthStorageInput, ACCOUNT_STATE_FIELDS_MAX_BYTES};

use super::storage::json_to_mpt_input;

async fn get_account_query<P: JsonRpcClient>(
    provider: &Provider<P>,
    block_number: u64,
    addr: Address,
    acct_pf_max_depth: usize,
) -> EthStorageInput {
    let block = provider.get_block(block_number).await.unwrap().unwrap();
    let pf = provider.get_proof(addr, vec![], Some(block_number.into())).await.unwrap();

    let mut input = json_to_mpt_input(pf, acct_pf_max_depth, 0);
    input.acct_pf.root_hash = block.state_root;
    input
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

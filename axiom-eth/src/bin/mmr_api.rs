//! Aided tool for generating Merkle Mountain Range proof for a block
//! This is just a wrapper call to the Axiom api endpoint
//!
//! Note this may not work on a block that is within the 1024 most recent (some additional handling is required for that)
use axiom_eth::batch_query::response::block_header::BLOCK_BATCH_DEPTH;
use clap::Parser;
use clap_num::maybe_hex;
use ethers_core::types::H256;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short, long = "block-number", value_parser=maybe_hex::<u32>)]
    block_number: u32,
    #[arg(long, default_value_t = 1)]
    chain_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MmrProof {
    mmr: Vec<H256>,
    claimed_block_hash: H256,
    merkle_proof: Vec<H256>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let block_number = args.block_number;
    let chain_id = args.chain_id;

    let client = reqwest::Client::new();
    let api_url = "https://api.axiom.xyz/v1/block/get_block_mmr_proof";

    let response = client
        .get(api_url)
        .query(&[("blockNumber", block_number), ("chainId", chain_id)])
        .send()
        .await?;
    let MmrProof { mmr: historical_mmr, claimed_block_hash: _, merkle_proof } =
        response.json::<MmrProof>().await?;
    let mut mmr_len = 0;
    for (i, peak) in historical_mmr.iter().enumerate() {
        if peak != &H256::zero() {
            mmr_len += 1 << i;
        }
    }
    let mmr_num_blocks = mmr_len << BLOCK_BATCH_DEPTH;
    let mmr = [vec![H256::zero(); BLOCK_BATCH_DEPTH], historical_mmr].concat();

    println!("mmr for blocks [0, {mmr_num_blocks}), mmr proof for block number {block_number}");
    println!(
        "{}",
        json!({
            "mmr": mmr,
            "mmrProof": merkle_proof
        })
    );

    Ok(())
}

#![allow(clippy::too_many_arguments)]
use ethers_core::{types::Chain, utils::hex::FromHex};
use ethers_providers::{Http, Provider, RetryClient};

use std::env::var;

pub mod account;
pub mod block;
pub mod receipt;
pub mod storage;
pub mod transaction;

pub fn get_provider_uri(chain: Chain) -> String {
    let key = var("ALCHEMY_KEY").expect("ALCHEMY_KEY environmental variable not set");
    format!("https://eth-{chain}.g.alchemy.com/v2/{key}")
}

pub fn setup_provider(chain: Chain) -> Provider<RetryClient<Http>> {
    let provider_uri = get_provider_uri(chain);
    Provider::new_client(&provider_uri, 10, 500).expect("could not instantiate HTTP Provider")
}

pub fn from_hex(s: &str) -> Vec<u8> {
    let s = if s.len() % 2 == 1 { format!("0{s}") } else { s.to_string() };
    Vec::from_hex(s).unwrap()
}

use crate::providers::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL};
use ethers_providers::{Http, Middleware, Provider};
use std::env::var;
use tokio::runtime::Runtime;

mod account;
#[cfg(feature = "aggregation")]
mod aggregation;
mod block_header;
mod row_consistency;
#[cfg(feature = "aggregation")]
mod scheduler;
mod storage;

fn setup_provider() -> Provider<Http> {
    let infura_id = var("INFURA_ID").expect("INFURA_ID environmental variable not set");
    let provider_url = format!("{MAINNET_PROVIDER_URL}{infura_id}");
    Provider::<Http>::try_from(provider_url.as_str()).expect("could not instantiate HTTP Provider")
}

fn setup_provider_goerli() -> Provider<Http> {
    let infura_id = var("INFURA_ID").expect("INFURA_ID environmental variable not set");
    let provider_url = format!("{GOERLI_PROVIDER_URL}{infura_id}");
    Provider::<Http>::try_from(provider_url.as_str()).expect("could not instantiate HTTP Provider")
}

fn get_latest_block_number() -> u64 {
    let provider = setup_provider();
    let rt = Runtime::new().unwrap();
    rt.block_on(provider.get_block_number()).unwrap().as_u64()
}

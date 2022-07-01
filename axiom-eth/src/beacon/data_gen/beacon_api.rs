use beacon_api_client::{mainnet::Client, StateId};
use itertools::Itertools;
use ssz_rs::prelude::*;
use std::{env::var, fs::File, io::Write};
use url::Url;

pub const MAINNET_URL: &str = "https://eth2-beacon-mainnet.nodereal.io/v1/";

pub fn setup_url() -> String {
    let nodereal_id = var("NODEREAL_ID").expect("NODEREAL_ID environmental variable not set");
    MAINNET_URL.to_owned() + &nodereal_id + "/"
}

pub async fn get_beacon_state_components(slot: u64) {
    let url = setup_url();
    let client = Client::new(Url::parse(&url).unwrap());
    let mut response = client.get_state(StateId::Slot(slot)).await.unwrap();
    let gt = hex::encode(response.genesis_time.hash_tree_root().expect("bad"));
    let gvr = hex::encode(response.genesis_validators_root);
    let slo = hex::encode(response.slot.hash_tree_root().expect("bad"));
    let fork = hex::encode(response.fork.hash_tree_root().expect("bad"));
    let lbh = hex::encode(response.latest_block_header.hash_tree_root().expect("bad"));
    let br = hex::encode(response.block_roots.hash_tree_root().unwrap());
    let sr = hex::encode(response.state_roots.hash_tree_root().unwrap());
    let hr = hex::encode(response.historical_roots.hash_tree_root().unwrap());
    let ed = hex::encode(response.eth1_data.hash_tree_root().unwrap());
    let edv = hex::encode(response.eth1_data_votes.hash_tree_root().unwrap());
    let edi = hex::encode(response.eth1_deposit_index.hash_tree_root().unwrap());
    let v = hex::encode(response.validators.hash_tree_root().unwrap());
    let b = hex::encode(response.balances.hash_tree_root().unwrap());
    let rm = hex::encode(response.randao_mixes.hash_tree_root().unwrap());
    let sl = hex::encode(response.slashings.hash_tree_root().unwrap());
    let pep = hex::encode(response.previous_epoch_attestations.hash_tree_root().unwrap());
    let cep = hex::encode(response.current_epoch_attestations.hash_tree_root().unwrap());
    let jb = hex::encode(response.justification_bits.hash_tree_root().unwrap());
    let pjc = hex::encode(response.previous_justified_checkpoint.hash_tree_root().unwrap());
    let cjc = hex::encode(response.current_justified_checkpoint.hash_tree_root().unwrap());
    let fc = hex::encode(response.finalized_checkpoint.hash_tree_root().unwrap());
    let roots = [
        gt, gvr, slo, fork, lbh, br, sr, hr, ed, edv, edi, v, b, rm, sl, pep, cep, jb, pjc, cjc, fc,
    ];
    let byte_roots = roots.iter().map(|v| hex::decode(v).unwrap()).collect_vec();
    let byte_roots =
        byte_roots.into_iter().map(|v| Vector::<u8, 32>::try_from(v).unwrap()).collect_vec();
    let mut byte_roots = Vector::<Vector<u8, 32>, 21>::try_from(byte_roots).unwrap();
    println!("{:?}", hex::encode(byte_roots.hash_tree_root().unwrap()));
    println!("{:?}", hex::encode(response.hash_tree_root().unwrap()));
    let new_response = client.get_state_root(StateId::Slot(slot)).await.unwrap();
    println!("{:?}", hex::encode(new_response));
    let mut components =
        File::create("src/beacon/data_gen/cached_computations/beacon_state_components.json")
            .unwrap();
    let obj = serde_json::to_string_pretty(&roots).unwrap();
    let _ = components.write_all(obj.as_bytes());
}

pub async fn get_all_validators(slot: u64) {
    let url = setup_url();
    let client = Client::new(Url::parse(&url).unwrap());
    let response = client.get_validators(StateId::Slot(slot), &[], &[]).await.unwrap();
    let mut file = File::create("src/beacon/data_gen/cached_computations/validators.json").unwrap();
    let response = response.into_iter().map(|r| r.validator).collect_vec();
    let obj = serde_json::to_string_pretty(&response).unwrap();
    let _ = file.write_all(obj.as_bytes());
}

pub async fn get_all_balances(slot: u64) {
    let url = setup_url();
    let client = Client::new(Url::parse(&url).unwrap());
    let response = client.get_balances(StateId::Slot(slot), &[]).await.unwrap();
    let mut file = File::create("src/beacon/data_gen/cached_computations/balances.json").unwrap();
    let response = response.into_iter().map(|r| r.balance).collect_vec();
    let obj = serde_json::to_string_pretty(&response).unwrap();
    let _ = file.write_all(obj.as_bytes());
}

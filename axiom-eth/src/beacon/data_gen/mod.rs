use crate::Field;
use halo2_base::{
    gates::RangeChip, halo2_proofs::halo2curves::bn256::Fr, utils::ScalarField, Context,
};
use itertools::Itertools;
use serde_json::{from_str, Map, Value};
use ssz_rs::prelude::*;

use crate::{
    beacon::types::SszUint64,
    providers::from_hex,
    sha256::sha256,
    ssz::{
        types::{SszBasicType, SszBasicTypeVector, SszStruct},
        SszChip,
    },
};

pub mod beacon_api;
#[cfg(test)]
pub mod test;

use self::beacon_api::{get_all_balances, get_all_validators, get_beacon_state_components};

use super::types::Validator;

pub const SLOT: u64 = 2375000;
pub const NUM_VALIDATORS: usize = 250399;
pub const TREE_DEPTH: usize = 20;
pub const BALANCE_TREE_DEPTH: usize = TREE_DEPTH - 2;

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct TestValidator {
    pub public_key: Vector<u8, 48>,
    pub withdrawal_credentials: Vector<u8, 32>,
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_eligibility_epoch: u64,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
    pub withdrawable_epoch: u64,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct TestValidatorInfo {
    pub bls_pub_key: Vector<u8, 48>,
    pub withdrawal_creds: Vector<u8, 32>,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct TestPair {
    pub first: u64,
    pub second: u64,
}

#[derive(Debug, Clone)]
pub struct SszPair<F: ScalarField> {
    pub first: SszUint64<F>,
    pub second: SszUint64<F>,
}

impl<F: Field> SszStruct<F> for SszPair<F> {
    fn hash_root(&self, ctx: &mut Context<F>, ssz: &SszChip<F>) -> crate::ssz::types::Chunk<F> {
        let first_root = self.first.hash_root(ctx, ssz);
        let second_root = self.second.hash_root(ctx, ssz);
        ssz.merkleize(ctx, [first_root, second_root].to_vec())
    }
}

pub fn get_validator_from_json(val: Value) -> TestValidator {
    let bls: String = serde_json::from_value(val["pubkey"].clone()).unwrap();
    let bls = Vector::<u8, 48>::try_from(from_hex(&bls[2..])).unwrap();
    let wc: String = serde_json::from_value(val["withdrawal_credentials"].clone()).unwrap();
    let wc = Vector::<u8, 32>::try_from(from_hex(&wc[2..])).unwrap();
    let eb: String = serde_json::from_value(val["effective_balance"].clone()).unwrap();
    let eb = from_str::<u64>(&eb).unwrap();
    let sl: bool = serde_json::from_value(val["slashed"].clone()).unwrap();
    let aee: String = serde_json::from_value(val["activation_eligibility_epoch"].clone()).unwrap();
    let aee = from_str::<u64>(&aee).unwrap();
    let ae: String = serde_json::from_value(val["activation_epoch"].clone()).unwrap();
    let ae = from_str::<u64>(&ae).unwrap();
    let we: String = serde_json::from_value(val["withdrawable_epoch"].clone()).unwrap();
    let we = from_str::<u64>(&we).unwrap();
    let ee: String = serde_json::from_value(val["exit_epoch"].clone()).unwrap();
    let ee = from_str::<u64>(&ee).unwrap();
    TestValidator {
        public_key: bls,
        withdrawal_credentials: wc,
        effective_balance: eb,
        slashed: sl,
        activation_eligibility_epoch: aee,
        activation_epoch: ae,
        exit_epoch: ee,
        withdrawable_epoch: we,
    }
}

pub fn get_validator_assigned_from_json(
    ctx: &mut Context<Fr>,
    range: &RangeChip<Fr>,
    val: Value,
) -> Validator<Fr> {
    let bls: String = serde_json::from_value(val["pubkey"].clone()).unwrap();
    let bls = from_hex(&bls[2..]);
    let bls = bls.into_iter().map(|b| b as u64).collect_vec();
    let wc: String = serde_json::from_value(val["withdrawal_credentials"].clone()).unwrap();
    let wc = from_hex(&wc[2..]);
    let wc = wc.into_iter().map(|w| w as u64).collect_vec();
    let eb: String = serde_json::from_value(val["effective_balance"].clone()).unwrap();
    let eb = from_str::<u64>(&eb).unwrap();
    let sl: bool = serde_json::from_value(val["slashed"].clone()).unwrap();
    let aee: String = serde_json::from_value(val["activation_eligibility_epoch"].clone()).unwrap();
    let aee = from_str::<u64>(&aee).unwrap();
    let ae: String = serde_json::from_value(val["activation_epoch"].clone()).unwrap();
    let ae = from_str::<u64>(&ae).unwrap();
    let we: String = serde_json::from_value(val["withdrawable_epoch"].clone()).unwrap();
    let we = from_str::<u64>(&we).unwrap();
    let ee: String = serde_json::from_value(val["exit_epoch"].clone()).unwrap();
    let ee = from_str::<u64>(&ee).unwrap();
    let bls = SszBasicTypeVector::new_from_ints(ctx, &range, bls, 8);
    let wc = SszBasicTypeVector::new_from_ints(ctx, &range, wc, 8);
    let eb = SszBasicType::new_from_int(ctx, &range, eb, 64);
    let eb = SszUint64::from(eb);
    let sl = SszBasicType::new_from_int(ctx, &range, sl as u64, 1);
    let aee = SszBasicType::new_from_int(ctx, &range, aee, 64);
    let aee = SszUint64::from(aee);
    let ae = SszBasicType::new_from_int(ctx, &range, ae, 64);
    let ae = SszUint64::from(ae);
    let we = SszBasicType::new_from_int(ctx, &range, we, 64);
    let we = SszUint64::from(we);
    let ee = SszBasicType::new_from_int(ctx, &range, ee, 64);
    let ee = SszUint64::from(ee);
    Validator::from(bls, wc, eb, sl, aee, ae, ee, we)
}

pub async fn get_all_data(slot: u64) {
    get_beacon_state_components(slot).await;
    get_all_validators(slot).await;
    get_all_balances(slot).await;
}

pub fn get_roots_and_zeroes() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let roots_str =
        std::fs::read_to_string("src/beacon/data_gen/cached_computations/roots.json").unwrap();
    let roots_vec: serde_json::Value = serde_json::from_str(roots_str.as_str()).unwrap();
    let roots_vec: Vec<String> = serde_json::from_value(roots_vec).unwrap();
    let roots_vec: Vec<Vec<u8>> = roots_vec.iter().map(|val| from_hex(&val)).collect();
    let zeroes_str =
        std::fs::read_to_string("src/beacon/data_gen/cached_computations/zeroes.json").unwrap();
    let zeroes_vec: serde_json::Value = serde_json::from_str(zeroes_str.as_str()).unwrap();
    let zeroes_vec: Vec<String> = serde_json::from_value(zeroes_vec).unwrap();
    let zeroes_vec: Vec<Vec<u8>> = zeroes_vec.iter().map(|val| from_hex(&val)).collect();
    (roots_vec, zeroes_vec)
}

pub fn get_balance_roots_and_zeroes() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let roots_str =
        std::fs::read_to_string("src/beacon/data_gen/cached_computations/balance_roots.json")
            .unwrap();
    let roots_vec: serde_json::Value = serde_json::from_str(roots_str.as_str()).unwrap();
    let roots_vec: Vec<String> = serde_json::from_value(roots_vec).unwrap();
    let roots_vec: Vec<Vec<u8>> = roots_vec.iter().map(|val| from_hex(&val)).collect();
    let zeroes_str =
        std::fs::read_to_string("src/beacon/data_gen/cached_computations/zeroes.json").unwrap();
    let zeroes_vec: serde_json::Value = serde_json::from_str(zeroes_str.as_str()).unwrap();
    let zeroes_vec: Vec<String> = serde_json::from_value(zeroes_vec).unwrap();
    let zeroes_vec: Vec<Vec<u8>> = zeroes_vec.iter().map(|val| from_hex(&val)).collect();
    (roots_vec, zeroes_vec)
}

pub fn get_validator_proof(idx: usize) -> Map<String, Value> {
    let (roots, zeroes) = get_roots_and_zeroes();
    assert!(idx < roots.len() / 2);
    let base_len = 40 - TREE_DEPTH;
    let mut base_path = vec![vec![0; 32]; base_len + 1];
    let mut len: Vec<u8> = vec![0; 32];
    let mut len_int = NUM_VALIDATORS;
    for i in 0..32 {
        len[i] = (len_int % 256) as u8;
        len_int /= 256;
    }
    base_path[0] = len;
    let mut base_dir = vec![0; base_len + 1];
    let mut root = roots[1].clone();
    for i in 0..base_len {
        base_path[base_len - i] = zeroes[TREE_DEPTH + i].clone();
        let mut root_clone = root.clone();
        root_clone.append(&mut base_path[base_len - i].clone());
        root = sha256(root_clone).to_vec();
    }
    let mut root_clone = root.clone();
    root_clone.append(&mut base_path[0].clone());
    root = sha256(root_clone).to_vec();
    let mut new_dir = vec![0; TREE_DEPTH];
    let mut dir_idx = idx;
    for i in 0..TREE_DEPTH {
        new_dir[40 - base_len - 1 - i] = dir_idx % 2;
        dir_idx /= 2;
    }
    let mut roots_idx = 1;
    let mut new_path = Vec::new();
    for i in 0..TREE_DEPTH {
        roots_idx = roots_idx * 2 + new_dir[i];
        new_path.push(roots[roots_idx ^ 1].clone());
    }
    base_path.append(&mut new_path);
    base_dir.append(&mut new_dir);
    let val = roots[roots_idx].clone();
    let mut map = Map::new();
    let root = hex::encode(root);
    let val = hex::encode(val);
    let proof = base_path.iter().map(|p| hex::encode(p)).collect_vec();
    map.insert("directions".to_owned(), base_dir.into());
    map.insert("val".to_owned(), val.into());
    map.insert("root_bytes".to_owned(), root.into());
    map.insert("proof".to_owned(), proof.into());
    map
}

pub fn get_balance_proof(idx: usize) -> Map<String, Value> {
    let (roots, zeroes) = get_balance_roots_and_zeroes();
    assert!(idx < roots.len() / 2);
    let base_len = 40 - TREE_DEPTH;
    let mut base_path = vec![vec![0; 32]; base_len + 1];
    let mut len: Vec<u8> = vec![0; 32];
    let mut len_int = NUM_VALIDATORS;
    for i in 0..32 {
        len[i] = (len_int % 256) as u8;
        len_int /= 256;
    }
    base_path[0] = len;
    let mut base_dir = vec![0; base_len + 1];
    let mut root = roots[1].clone();
    for i in 0..base_len {
        base_path[base_len - i] = zeroes[BALANCE_TREE_DEPTH + i].clone();
        let mut root_clone = root.clone();
        root_clone.append(&mut base_path[base_len - i].clone());
        root = sha256(root_clone).to_vec();
    }
    let mut root_clone = root.clone();
    root_clone.append(&mut base_path[0].clone());
    root = sha256(root_clone).to_vec();
    let mut new_dir = vec![0; BALANCE_TREE_DEPTH];
    let mut dir_idx = idx / 4;
    for i in 0..BALANCE_TREE_DEPTH {
        new_dir[BALANCE_TREE_DEPTH - 1 - i] = dir_idx % 2;
        dir_idx /= 2;
    }
    let mut roots_idx = 1;
    let mut new_path = Vec::new();
    for i in 0..BALANCE_TREE_DEPTH {
        roots_idx = roots_idx * 2 + new_dir[i];
        new_path.push(roots[roots_idx ^ 1].clone());
    }
    base_path.append(&mut new_path);
    base_dir.append(&mut new_dir);
    let val = roots[roots_idx].clone();
    let mut map = Map::new();
    let root = hex::encode(root);
    let val = hex::encode(val);
    let proof = base_path.iter().map(|p| hex::encode(p)).collect_vec();
    map.insert("directions".to_owned(), base_dir.into());
    map.insert("val".to_owned(), val.into());
    map.insert("root_bytes".to_owned(), root.into());
    map.insert("proof".to_owned(), proof.into());
    map
}

pub fn get_validator_list_proof() -> (Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
    let roots_str = std::fs::read_to_string(
        "src/beacon/data_gen/cached_computations/beacon_state_components.json",
    )
    .unwrap();
    let roots_vec: serde_json::Value = serde_json::from_str(roots_str.as_str()).unwrap();
    let roots_vec: Vec<String> = serde_json::from_value(roots_vec).unwrap();
    let mut roots_vec: Vec<Vec<u8>> = roots_vec.iter().map(|val| from_hex(&val)).collect();
    roots_vec.resize(32, vec![0 as u8; 32]);
    let mut roots = vec![vec![]; 32];
    roots.append(&mut roots_vec);
    for i in 1..32 {
        let idx = 32 - i;
        let mut root_concat = roots[2 * idx].clone();
        root_concat.append(&mut roots[2 * idx + 1].clone());
        let new_root = sha256(root_concat).to_vec();
        roots[idx] = new_root;
    }
    let list_proof = vec![
        roots[3].clone(),
        roots[4].clone(),
        roots[11].clone(),
        roots[20].clone(),
        roots[42].clone(),
    ];
    let list_dir: Vec<u8> = vec![0, 1, 0, 1, 1];
    let list_root = roots[1].clone();
    (list_proof, list_root, list_dir)
}

pub fn get_balance_list_proof() -> (Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
    let roots_str = std::fs::read_to_string(
        "src/beacon/data_gen/cached_computations/beacon_state_components.json",
    )
    .unwrap();
    let roots_vec: serde_json::Value = serde_json::from_str(roots_str.as_str()).unwrap();
    let roots_vec: Vec<String> = serde_json::from_value(roots_vec).unwrap();
    let mut roots_vec: Vec<Vec<u8>> = roots_vec.iter().map(|val| from_hex(&val)).collect();
    roots_vec.resize(32, vec![0 as u8; 32]);
    let mut roots = vec![vec![]; 32];
    roots.append(&mut roots_vec);
    for i in 1..32 {
        let idx = 32 - i;
        let mut root_concat = roots[2 * idx].clone();
        root_concat.append(&mut roots[2 * idx + 1].clone());
        let new_root = sha256(root_concat).to_vec();
        roots[idx] = new_root;
    }
    let list_proof = vec![
        roots[3].clone(),
        roots[4].clone(),
        roots[10].clone(),
        roots[23].clone(),
        roots[45].clone(),
    ];
    let list_dir: Vec<u8> = vec![0, 1, 1, 0, 0];
    let list_root = roots[1].clone();
    (list_proof, list_root, list_dir)
}

pub fn get_validator_into_beacon(idx: usize) -> Map<String, Value> {
    let mut map = get_validator_proof(idx);
    let (list_proof, list_root, mut list_dir) = get_validator_list_proof();
    map["root_bytes"] = hex::encode(&list_root).into();
    let mut dirs: Vec<u8> = serde_json::from_value(map["directions"].clone()).unwrap();
    let mut proof: Vec<String> = serde_json::from_value(map["proof"].clone()).unwrap();
    let mut list_proof = list_proof.into_iter().map(|p| hex::encode(&p)).collect_vec();
    list_dir.append(&mut dirs);
    list_proof.append(&mut proof);
    map["directions"] = list_dir.into();
    map["proof"] = list_proof.into();
    map
}

pub fn get_balance_into_beacon(idx: usize) -> Map<String, Value> {
    let bal_str =
        std::fs::read_to_string("src/beacon/data_gen/cached_computations/balances.json").unwrap();
    let vec_val: serde_json::Value = serde_json::from_str(bal_str.as_str()).unwrap();
    let vec_val: Vec<serde_json::Value> = serde_json::from_value(vec_val).unwrap();
    let val = vec_val[idx].clone();
    let balance: u64 = serde_json::from_value(val).unwrap();
    let mut map = get_balance_proof(idx);
    let (list_proof, list_root, mut list_dir) = get_balance_list_proof();
    map["root_bytes"] = hex::encode(&list_root).into();
    let mut dirs: Vec<u8> = serde_json::from_value(map["directions"].clone()).unwrap();
    let mut proof: Vec<String> = serde_json::from_value(map["proof"].clone()).unwrap();
    let mut list_proof = list_proof.into_iter().map(|p| hex::encode(&p)).collect_vec();
    list_dir.append(&mut dirs);
    list_proof.append(&mut proof);
    map["directions"] = list_dir.into();
    map["proof"] = list_proof.into();
    let mut new_map = Map::new();
    new_map.insert("proof".to_owned(), Value::Object(map));
    new_map.insert("idx".to_owned(), Value::Number(idx.into()));
    new_map.insert("balance".to_owned(), Value::Number(balance.into()));
    new_map
}

pub fn get_validator_info_into_beacon(idx: usize) -> Map<String, Value> {
    let val_str =
        std::fs::read_to_string("src/beacon/data_gen/cached_computations/validators.json").unwrap();
    let vec_val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let vec_val: Vec<serde_json::Value> = serde_json::from_value(vec_val).unwrap();
    let pow2 = 8;
    let mut root_vec = vec![Vec::new(); 8];
    let val = vec_val[idx].clone();
    let bls: String = serde_json::from_value(val["pubkey"].clone()).unwrap();
    let bls_string = bls.clone();
    let mut bls = Vector::<u8, 48>::try_from(from_hex(&bls[2..])).unwrap();
    let wc: String = serde_json::from_value(val["withdrawal_credentials"].clone()).unwrap();
    let wc_string = wc.clone();
    let mut wc = Vector::<u8, 32>::try_from(from_hex(&wc[2..])).unwrap();
    let eb: String = serde_json::from_value(val["effective_balance"].clone()).unwrap();
    let mut eb = from_str::<u64>(&eb).unwrap();
    let mut sl: bool = serde_json::from_value(val["slashed"].clone()).unwrap();
    let aee: String = serde_json::from_value(val["activation_eligibility_epoch"].clone()).unwrap();
    let mut aee = from_str::<u64>(&aee).unwrap();
    let ae: String = serde_json::from_value(val["activation_epoch"].clone()).unwrap();
    let mut ae = from_str::<u64>(&ae).unwrap();
    let we: String = serde_json::from_value(val["withdrawable_epoch"].clone()).unwrap();
    let mut we = from_str::<u64>(&we).unwrap();
    let ee: String = serde_json::from_value(val["exit_epoch"].clone()).unwrap();
    let mut ee = from_str::<u64>(&ee).unwrap();
    let bls = hex::encode(bls.hash_tree_root().unwrap());
    let wc = hex::encode(wc.hash_tree_root().unwrap());
    let eb = hex::encode(eb.hash_tree_root().unwrap());
    let sl = hex::encode(sl.hash_tree_root().unwrap());
    let aee = hex::encode(aee.hash_tree_root().unwrap());
    let ae = hex::encode(ae.hash_tree_root().unwrap());
    let we = hex::encode(we.hash_tree_root().unwrap());
    let ee = hex::encode(ee.hash_tree_root().unwrap());
    let app = vec![bls, wc, eb, sl, aee, ae, we, ee];
    let mut app = app.into_iter().map(|s| from_hex(&s)).collect_vec();
    root_vec.append(&mut app);
    for i in 1..pow2 {
        let idx = pow2 - i;
        let mut root_concat = root_vec[2 * idx].clone();
        root_concat.append(&mut root_vec[2 * idx + 1].clone());
        let new_root = sha256(root_concat).to_vec();
        root_vec[idx] = new_root;
    }
    let root_vec = root_vec.iter().map(|r| hex::encode(r)).collect_vec();
    let mut map = get_validator_into_beacon(idx);
    let mut dirs: Vec<u8> = serde_json::from_value(map["directions"].clone()).unwrap();
    let mut proof: Vec<String> = serde_json::from_value(map["proof"].clone()).unwrap();
    proof.push(root_vec[3].clone());
    proof.push(root_vec[5].clone());
    dirs.append(&mut vec![0, 0]);
    map["directions"] = dirs.into();
    map["proof"] = proof.into();
    map["val"] = serde_json::Value::String(root_vec[4].clone());
    let mut new_map = Map::new();
    new_map.insert("idx".to_owned(), serde_json::Value::Number(idx.into()));
    new_map.insert("public_key".to_owned(), serde_json::Value::String(bls_string));
    new_map.insert("withdrawal_credentials".to_owned(), serde_json::Value::String(wc_string));
    let proof = Value::Object(map);
    new_map.insert("proof".to_owned(), proof);
    new_map
}

use std::{
    fs::File,
    io::{BufWriter, Write},
};

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use itertools::Itertools;
use serde_json::{from_str, Value};
use ssz_rs::{List, Merkleized, Vector};

use crate::{
    beacon::{
        data_gen::{
            from_hex, get_all_balances, get_all_data, get_all_validators,
            get_beacon_state_components, get_roots_and_zeroes, get_validator_assigned_from_json,
            get_validator_from_json, SszPair, TestPair, TestValidator,
        },
        types::SszUint64,
    },
    rlc::circuit::builder::RlcCircuitBuilder,
    sha256::{sha256, Sha256Chip},
    ssz::{
        types::{SszBasicType, SszBasicTypeVector, SszList, SszStruct, SszVector},
        SszChip,
    },
};

use super::{get_validator_into_beacon, get_validator_proof, BALANCE_TREE_DEPTH, TREE_DEPTH};

#[test]
pub fn get_bls_root() {
    let val_str =
        std::fs::read_to_string("src/beacon/tests/generated_tests/validator.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let bls: String = serde_json::from_value(val["pubkey"].clone()).unwrap();
    let mut bls = Vector::<u8, 48>::try_from(from_hex(&bls[2..])).unwrap();
    let root = bls.hash_tree_root().expect("bad");
    println!("{:?}", hex::encode(root));
}

#[test]
pub fn get_bls_root_assigned() {
    let val_str =
        std::fs::read_to_string("src/beacon/tests/generated_tests/validator.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let bls: String = serde_json::from_value(val["pubkey"].clone()).unwrap();
    let bls = from_hex(&bls[2..]);
    let bls = bls.into_iter().map(|b| b as u64).collect_vec();
    let mut builder = RlcCircuitBuilder::<Fr>::new(false, 10).use_lookup_bits(8);
    let range = builder.range_chip();
    let ctx = builder.base.main(0);
    let bls = SszBasicTypeVector::new_from_ints(ctx, &range, bls, 8);
    let ssz = SszChip::new(None, &range, Sha256Chip::new(&range));
    println!("{:?}", bls.hash_root(ctx, &ssz));
}

#[test]
pub fn get_eb_root() {
    let val_str =
        std::fs::read_to_string("src/beacon/tests/generated_tests/validator.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let eb: String = serde_json::from_value(val["effective_balance"].clone()).unwrap();
    let mut eb = from_str::<u64>(&eb).unwrap();
    let root = eb.hash_tree_root().expect("bad");
    println!("{:?}", hex::encode(root));
}

#[test]
pub fn get_eb_root_assigned() {
    let val_str =
        std::fs::read_to_string("src/beacon/tests/generated_tests/validator.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let eb: String = serde_json::from_value(val["effective_balance"].clone()).unwrap();
    let eb = from_str::<u64>(&eb).unwrap();
    let mut builder = RlcCircuitBuilder::<Fr>::new(false, 10).use_lookup_bits(8);
    let range = builder.range_chip();
    let ctx = builder.base.main(0);
    let eb = SszBasicType::new_from_int(ctx, &range, eb, 64);
    let eb = SszUint64::from(eb);
    let ssz = SszChip::new(None, &range, Sha256Chip::new(&range));
    println!("{:?}", eb.hash_root(ctx, &ssz));
}

#[test]
pub fn get_sl_root() {
    let val_str =
        std::fs::read_to_string("src/beacon/tests/generated_tests/validator.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let mut sl: bool = serde_json::from_value(val["slashed"].clone()).unwrap();
    let root = sl.hash_tree_root().expect("bad");
    println!("{:?}", hex::encode(root));
}

#[test]
pub fn get_sl_root_assigned() {
    let val_str =
        std::fs::read_to_string("src/beacon/tests/generated_tests/validator.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let sl: bool = serde_json::from_value(val["slashed"].clone()).unwrap();
    let mut builder = RlcCircuitBuilder::<Fr>::new(false, 10).use_lookup_bits(8);
    let range = builder.range_chip();
    let ctx = builder.base.main(0);
    let sl = SszBasicType::new_from_int(ctx, &range, sl as u64, 1);
    let ssz = SszChip::new(None, &range, Sha256Chip::new(&range));
    println!("{:?}", sl.hash_root(ctx, &ssz));
}

#[test]
pub fn get_pair_root() {
    let val_str = std::fs::read_to_string("src/beacon/tests/generated_tests/pair.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let first: u64 = serde_json::from_value(val["first"].clone()).unwrap();
    let second: u64 = serde_json::from_value(val["second"].clone()).unwrap();
    let mut val = TestPair { first, second };
    let root = val.hash_tree_root().expect("bad");
    println!("{:?}", hex::encode(root));
}

#[test]
pub fn get_pair_root_assigned() {
    let val_str = std::fs::read_to_string("src/beacon/tests/generated_tests/pair.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let first: u64 = serde_json::from_value(val["first"].clone()).unwrap();
    let second: u64 = serde_json::from_value(val["second"].clone()).unwrap();
    let mut builder = RlcCircuitBuilder::new(false, 10).use_lookup_bits(8);
    let range = builder.range_chip();
    let ctx = builder.base.main(0);
    let first = SszBasicType::new_from_int(ctx, &range, first, 64);
    let first: SszUint64<Fr> = SszUint64::from(first);
    let second = SszBasicType::new_from_int(ctx, &range, second, 64);
    let second = SszUint64::from(second);
    let val = SszPair { first, second };
    let ssz = SszChip::new(None, &range, Sha256Chip::new(&range));
    println!("{:?}", val.hash_root(ctx, &ssz));
}

#[test]
pub fn get_validator_vec_root() {
    let val_str =
        std::fs::read_to_string("src/beacon/tests/generated_tests/validator.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let val = get_validator_from_json(val);
    let val_vec = vec![val.clone(), val.clone(), val];
    let mut val_vec = Vector::<TestValidator, 3>::try_from(val_vec).unwrap();
    let root = val_vec.hash_tree_root().expect("bad");
    println!("{:?}", hex::encode(root));
}

#[test]
pub fn get_validator_vec_root_assigned() {
    let val_str =
        std::fs::read_to_string("src/beacon/tests/generated_tests/validator.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let mut builder = RlcCircuitBuilder::new(false, 10).use_lookup_bits(8);
    let range = builder.range_chip();
    let ctx = builder.base.main(0);
    let val = get_validator_assigned_from_json(ctx, &range, val);
    let ssz = SszChip::new(None, &range, Sha256Chip::new(&range));
    let val_vec = vec![val.clone(), val.clone(), val];
    let val_vec = SszVector { values: val_vec };
    println!("{:?}", val_vec.hash_root(ctx, &ssz));
}

#[test]
pub fn get_validator_list_root() {
    let val_str =
        std::fs::read_to_string("src/beacon/tests/generated_tests/validator.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let val = get_validator_from_json(val);
    let val_vec = vec![val.clone(), val.clone()];
    let mut val_vec = List::<TestValidator, 3>::try_from(val_vec).unwrap();
    let root = val_vec.hash_tree_root().expect("bad");
    println!("{:?}", hex::encode(root));
}

#[test]
pub fn get_validator_list_root_assigned() {
    let val_str =
        std::fs::read_to_string("src/beacon/tests/generated_tests/validator.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let mut builder = RlcCircuitBuilder::new(false, 10).use_lookup_bits(8);
    let range = builder.range_chip();
    let ctx = builder.base.main(0);
    let val = get_validator_assigned_from_json(ctx, &range, val);
    let ssz = SszChip::new(None, &range, Sha256Chip::new(&range));
    let val_vec = vec![val.clone(), val.clone(), val];
    let two = ctx.load_witness(Fr::from(2));
    let val_vec = SszList { values: val_vec, len: two };
    println!("{:?}", val_vec.hash_root(ctx, &ssz));
}

#[test]
pub fn get_validator_root() {
    let val_str =
        std::fs::read_to_string("src/beacon/tests/generated_tests/validator.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let mut val = get_validator_from_json(val);
    let root = val.hash_tree_root().expect("bad");
    println!("{:?}", hex::encode(root));
}

#[test]
pub fn get_validator_root_assigned() {
    let val_str =
        std::fs::read_to_string("src/beacon/tests/generated_tests/validator.json").unwrap();
    let val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let mut builder = RlcCircuitBuilder::new(false, 10).use_lookup_bits(8);
    let range = builder.range_chip();
    let ctx = builder.base.main(0);
    let val = get_validator_assigned_from_json(ctx, &range, val);
    let ssz = SszChip::new(None, &range, Sha256Chip::new(&range));
    println!("{:?}", val.hash_root(ctx, &ssz));
}

#[tokio::test]
pub async fn test_beacon_state() {
    get_beacon_state_components(2375000).await;
}

#[tokio::test]
pub async fn test_validators() {
    get_all_validators(2375000).await;
}

#[tokio::test]
pub async fn test_balances() {
    get_all_balances(2375000).await;
}

#[tokio::test]
pub async fn test_beacon_state_and_validators_and_balances() {
    get_all_data(2375000).await;
}

#[test]
pub fn get_all_validators_root() {
    let val_str =
        std::fs::read_to_string("src/beacon/data_gen/cached_computations/validators.json").unwrap();
    let vec_val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let vec_val: Vec<serde_json::Value> = serde_json::from_value(vec_val).unwrap();
    let len = vec_val.len();
    let base: usize = 2;
    let pow2 = base.pow(TREE_DEPTH as u32);
    let total_depth = 40;
    let mut root_vec = vec![Vec::new(); pow2];
    let mut z_roots = vec![vec![0; 32]];
    for i in 0..len {
        let val = vec_val[i].clone();
        let mut val = get_validator_from_json(val);
        let root = val.hash_tree_root().expect("bad");
        root_vec.push(from_hex(&hex::encode(root)));
    }
    for _ in len..pow2 {
        let zeroes: Vec<u8> = vec![0; 32];
        root_vec.push(zeroes);
    }
    for i in 1..pow2 {
        let idx = pow2 - i;
        let mut root_concat = root_vec[2 * idx].clone();
        root_concat.append(&mut root_vec[2 * idx + 1].clone());
        let new_root = sha256(root_concat).to_vec();
        root_vec[idx] = new_root;
    }
    for i in 1..total_depth {
        let mut z_root = z_roots[i - 1].clone();
        z_root.append(&mut z_roots[i - 1].clone());
        z_roots.push(sha256(z_root).to_vec());
    }
    let mut roots = File::create("src/beacon/data_gen/cached_computations/roots.json")
        .expect("Unable to create file");
    let root_vec = root_vec.iter().map(|r| hex::encode(r)).collect_vec();
    let roots_str = serde_json::to_string_pretty(&root_vec).unwrap();
    let _ = roots.write_all(roots_str.as_bytes());
    let mut zeroes = File::create("src/beacon/data_gen/cached_computations/zeroes.json")
        .expect("Unable to create file");
    let z_roots = z_roots.iter().map(|r| hex::encode(r)).collect_vec();
    let z_str = serde_json::to_string_pretty(&z_roots).unwrap();
    let _ = zeroes.write_all(z_str.as_bytes());
}

#[test]
pub fn get_all_balances_root() {
    let val_str =
        std::fs::read_to_string("src/beacon/data_gen/cached_computations/balances.json").unwrap();
    let vec_val: serde_json::Value = serde_json::from_str(val_str.as_str()).unwrap();
    let mut vec_val: Vec<u64> = serde_json::from_value(vec_val).unwrap();
    let len = vec_val.len();
    vec_val.resize(4 * ((len + 3) / 4), 0);
    let base: usize = 2;
    let pow2 = base.pow(BALANCE_TREE_DEPTH as u32);
    let mut root_vec = vec![Vec::new(); pow2];
    for i in 0..(len + 3) / 4 {
        let mut val = Vector::<u64, 4>::try_from(vec![
            vec_val[4 * i],
            vec_val[4 * i + 1],
            vec_val[4 * i + 2],
            vec_val[4 * i + 3],
        ])
        .unwrap();
        let root = val.hash_tree_root().expect("bad");
        root_vec.push(from_hex(&hex::encode(root)));
    }
    for _ in (len + 3) / 4..pow2 {
        let zeroes: Vec<u8> = vec![0; 32];
        root_vec.push(zeroes);
    }
    for i in 1..pow2 {
        let idx = pow2 - i;
        let mut root_concat = root_vec[2 * idx].clone();
        root_concat.append(&mut root_vec[2 * idx + 1].clone());
        let new_root = sha256(root_concat).to_vec();
        root_vec[idx] = new_root;
    }
    let mut roots = File::create("src/beacon/data_gen/cached_computations/balance_roots.json")
        .expect("Unable to create file");
    let root_vec = root_vec.iter().map(|r| hex::encode(r)).collect_vec();
    let roots_str = serde_json::to_string_pretty(&root_vec).unwrap();
    let _ = roots.write_all(roots_str.as_bytes());
}

#[test]
pub fn test_get_roots_and_zeroes() {
    let (r, z) = get_roots_and_zeroes();
    println!("{:?}", r.len());
    println!("{:?}", z.len());
}

#[test]
pub fn get_validator_into_beacon1() {
    let map = get_validator_into_beacon(1);
    let proof = Value::Object(map);
    let file = File::create("src/ssz/tests/merkle_proof/real_beacon_proof.json").unwrap();
    let mut writer = BufWriter::new(file);
    let _ = serde_json::to_writer_pretty(&mut writer, &proof);
    let _ = writer.flush();
}

#[test]
pub fn get_validator1() {
    let map = get_validator_proof(1);
    let proof = Value::Object(map);
    let file = File::create("src/ssz/tests/merkle_proof/real_proof.json").unwrap();
    let mut writer = BufWriter::new(file);
    let _ = serde_json::to_writer_pretty(&mut writer, &proof);
    let _ = writer.flush();
}

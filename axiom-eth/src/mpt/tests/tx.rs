#![allow(clippy::too_many_arguments)]
use super::*;
use cita_trie::{self, MemoryDB, PatriciaTrie, Trie};
use ethers_core::utils::keccak256;
use hasher::HasherKeccak;
use std::sync::Arc;
use test_case::test_case;

// Max Key Length: 3
// Max Proof Length for noninclusion: 3
// Max Proof Length for inclusion: 6

fn mpt_direct_input(
    value: Vec<u8>,
    proof: Vec<Vec<u8>>,
    hash: Vec<u8>,
    key: Vec<u8>,
    slot_is_empty: bool,
    max_depth: usize,
    max_key_byte_len: usize,
    key_byte_len: Option<usize>,
) -> MPTInput {
    let value_max_byte_len = 48;

    MPTInput {
        path: key.into(),
        value,
        root_hash: H256::from_slice(hash.as_slice()),
        proof,
        slot_is_empty,
        value_max_byte_len,
        max_depth,
        max_key_byte_len,
        key_byte_len,
    }
}

fn verify_key_val(
    trie: &PatriciaTrie<MemoryDB, HasherKeccak>,
    key: Vec<u8>,
    val: Vec<u8>,
    root: Vec<u8>,
    slot_is_empty: bool,
    bad_proof: bool,
    distort_idx: Option<Vec<i32>>,
    case_type: usize,
) -> bool {
    if case_type == 0 {
        verify_key_val_loose(trie, key, val, root, slot_is_empty, bad_proof, distort_idx)
    } else if case_type == 1 {
        verify_key_val_tight(trie, key, val, root, slot_is_empty, bad_proof, distort_idx)
    } else if case_type == 2 {
        verify_key_val_fixed(trie, key, val, root, slot_is_empty, bad_proof, distort_idx)
    } else {
        false
    }
}

fn verify_key_val_loose(
    trie: &PatriciaTrie<MemoryDB, HasherKeccak>,
    key: Vec<u8>,
    val: Vec<u8>,
    root: Vec<u8>,
    slot_is_empty: bool,
    bad_proof: bool,
    distort_idx: Option<Vec<i32>>,
) -> bool {
    let params = default_params();
    let key_byte_len = key.len();
    let mut proof = trie.get_proof(&key).unwrap();
    if bad_proof {
        let idx = match distort_idx {
            Some(_idx) => _idx,
            None => {
                // assert!(false);
                vec![0x00]
            }
        };
        proof = distort_proof(proof, idx);
    }
    let input =
        mpt_direct_input(val.to_vec(), proof, root, key, slot_is_empty, 6, 32, Some(key_byte_len)); // depth = max_depth
    let k = params.base.k as u32;
    let circuit = test_mpt_circuit::<Fr>(CircuitBuilderStage::Mock, params, input);
    let instances = circuit.instances();
    let prover = MockProver::run(k, &circuit, instances).unwrap();
    prover.verify().is_ok()
}

fn verify_key_val_tight(
    trie: &PatriciaTrie<MemoryDB, HasherKeccak>,
    key: Vec<u8>,
    val: Vec<u8>,
    root: Vec<u8>,
    slot_is_empty: bool,
    bad_proof: bool,
    distort_idx: Option<Vec<i32>>,
) -> bool {
    let params = default_params();
    let key_byte_len = key.len();
    let mut proof = trie.get_proof(&key).unwrap();
    if bad_proof {
        let idx = match distort_idx {
            Some(_idx) => _idx,
            None => {
                // assert!(false);
                vec![0x00]
            }
        };
        proof = distort_proof(proof, idx);
    }
    let proof_len = proof.len() + slot_is_empty as usize;
    let input = mpt_direct_input(
        val.to_vec(),
        proof,
        root,
        key,
        slot_is_empty,
        proof_len,
        key_byte_len,
        Some(key_byte_len),
    ); // depth = max_depth
    let k = params.base.k as u32;
    let circuit = test_mpt_circuit::<Fr>(CircuitBuilderStage::Mock, params, input);
    let instances = circuit.instances();
    let prover = MockProver::run(k, &circuit, instances).unwrap();
    prover.verify().is_ok()
}

fn verify_key_val_fixed(
    trie: &PatriciaTrie<MemoryDB, HasherKeccak>,
    key: Vec<u8>,
    val: Vec<u8>,
    root: Vec<u8>,
    slot_is_empty: bool,
    bad_proof: bool,
    distort_idx: Option<Vec<i32>>,
) -> bool {
    let params = default_params();
    let key_byte_len = key.len();
    let mut proof = trie.get_proof(&key).unwrap();
    if bad_proof {
        let idx = match distort_idx {
            Some(_idx) => _idx,
            None => {
                // assert!(false);
                vec![0x00]
            }
        };
        proof = distort_proof(proof, idx);
    }
    let input =
        mpt_direct_input(val.to_vec(), proof, root, key, slot_is_empty, 6, key_byte_len, None); // depth = max_depth
    let k = params.base.k as u32;
    let circuit = test_mpt_circuit::<Fr>(CircuitBuilderStage::Mock, params, input);
    let instances = circuit.instances();
    let prover = MockProver::run(k, &circuit, instances).unwrap();
    prover.verify().is_ok()
}

fn gen_tx_tree(
    num_keys: usize,
    rand_vals: bool,
    val_max_bytes: usize,
) -> (PatriciaTrie<MemoryDB, HasherKeccak>, Vec<Vec<u8>>) {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());
    let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
    let mut vals: Vec<Vec<u8>> = Vec::new();
    let mut val = [
        0x43, 0x52, 0x59, 0x50, 0x54, 0x4f, 0x50, 0x55, 0x4e, 0x4b, 0x53, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x16,
    ]
    .to_vec();
    for idx in 0..num_keys {
        let key = rlp::encode(&from_hex(&format!("{idx:x}").to_string())).to_vec();
        if rand_vals {
            let val_len = if val_max_bytes == 32 { 32 } else { 32 + idx % (val_max_bytes - 32) };
            val = keccak256(val).to_vec();
            val.resize(val_len, 0x00);
        }
        let val2 = val.clone();
        let val3 = val.clone();
        vals.push(val3);
        trie.insert(key, val2).unwrap();
    }
    let root = trie.root().unwrap();
    trie = PatriciaTrie::from(Arc::clone(&memdb), Arc::clone(&hasher), &root).unwrap();
    (trie, vals)
}

fn distort_proof(proof: Vec<Vec<u8>>, idx: Vec<i32>) -> Vec<Vec<u8>> {
    let mut proof2 = proof.clone();
    for id in idx {
        let realid = if id >= 0 { id as usize } else { proof.len() - id.unsigned_abs() as usize };
        assert!(realid < proof.len());
        proof2[realid] = distort(proof2[realid].clone());
    }
    proof2
}

fn distort(val: Vec<u8>) -> Vec<u8> {
    let mut val2 = val.clone();
    for i in 0..val.len() {
        val2[i] = 255 - val[i];
    }
    val2
}

#[test_case(1, false; "1 leaf, nonrand vals")]
#[test_case(2, false; "2 keys, nonrand vals")]
#[test_case(20, false; "20 keys, nonrand vals")]
#[test_case(200, false; "200 keys, nonrand vals")]
#[test_case(1, true; "1 leaf, rand vals")]
#[test_case(2, true; "2 keys, rand vals")]
#[test_case(20, true; "20 keys, rand vals")]
#[test_case(200, true; "200 keys, rand vals")]
fn pos_full_tree_test_inclusion(num_keys: usize, randvals: bool) {
    let (mut trie, vals) = gen_tx_tree(num_keys, randvals, 48);
    for idx in 0..(num_keys + 19) / 20 {
        let key = rlp::encode(&from_hex(&format!("{:x}", (20 * idx)).to_string())).to_vec();
        let val = vals[idx * 20].clone();
        let root = trie.root().unwrap();
        assert!(verify_key_val(&trie, key, val, root, false, false, None, 0));
    }
}

#[test_case(18, 1; "trie has 0x01, 0x10, 0x11, 2 branches")]
fn pos_test_inclusion(num_keys: usize, idx: usize) {
    let (mut trie, vals) = gen_tx_tree(num_keys, true, 48);

    let key = rlp::encode(&from_hex(&format!("{idx:x}"))).to_vec();
    let val = vals[idx].clone();
    let root = trie.root().unwrap();
    assert!(verify_key_val(&trie, key, val, root, false, false, None, 0));
}

#[test_case(1, false, 0; "1 leaf, nonrand vals, loose")]
#[test_case(200, false, 0; "200 keys, nonrand vals, loose")]
#[test_case(1, true, 0; "1 leaf, rand vals, loose")]
#[test_case(200, true, 0; "200 keys, rand vals, loose")]
#[test_case(1, true, 1; "1 leaf, rand vals, tight")]
#[test_case(200, true, 1; "200 keys, rand vals, tight")]
#[test_case(1, true, 2; "1 leaf, rand vals, fixed")]
#[test_case(200, true, 2; "200 keys, rand vals, fixed")]
fn neg_full_tree_test_inclusion_badval(num_keys: usize, randvals: bool, case_type: usize) {
    let (mut trie, _) = gen_tx_tree(num_keys, randvals, 48);
    for idx in 0..(num_keys + 19) / 20 {
        let key = rlp::encode(&from_hex(&format!("{:x}", (20 * idx)).to_string())).to_vec();
        let val = [0x00; 32];
        let root = trie.root().unwrap();
        assert!(!verify_key_val(&trie, key, val.to_vec(), root, false, false, None, case_type));
    }
}

#[test_case(1, 0; "1 leaf, loose")]
#[test_case(200, 0; "200 keys, loose")]
#[test_case(1, 1; "1 leaf, tight")]
#[test_case(200, 1; "200 keys, tight")]
#[test_case(1, 2; "1 leaf, fixed")]
#[test_case(200, 2; "200 keys, fixed")]
fn pos_test_noninclusion(num_keys: usize, case_type: usize) {
    let _ = env_logger::builder().is_test(true).try_init();
    let (mut trie, _) = gen_tx_tree(num_keys, true, 48);
    for i in 0..10 {
        let idx = num_keys + 20 * i;
        let key = rlp::encode(&from_hex(&format!("{idx:x}").to_string())).to_vec();
        let val = [
            0x43, 0x52, 0x59, 0x50, 0x54, 0x4f, 0x50, 0x55, 0x4e, 0x4b, 0x53, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x16,
        ];
        let root = trie.root().unwrap();
        assert!(verify_key_val(&trie, key, val.to_vec(), root, true, false, None, case_type),);
    }
}

#[test_case(140, false, 1; "undercut by 1 inclusion")]
#[test_case(8, true, 1; "1 depth inclusion")]
#[test_case(300, false, 1; "undercut by 1 noninclusion")]
#[test_case(350, true, 1; "1 depth noninclusion")]
#[test_case(350, false, 0; "undercut by 0 noninclusion")]
fn neg_invalid_max_depth(idx: usize, zero_start: bool, offset: usize) {
    let (mut trie, _) = gen_tx_tree(200, true, 48);
    let key = rlp::encode(&from_hex(&format!("{idx:x}"))).to_vec();
    let val = [
        0x43, 0x52, 0x59, 0x50, 0x54, 0x4f, 0x50, 0x55, 0x4e, 0x4b, 0x53, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x16,
    ];
    let root = trie.root().unwrap();
    let key_byte_len = key.len();
    let proof = trie.get_proof(&key).unwrap();
    let proof_len = proof.len();
    let depth = if zero_start { offset } else { proof_len - offset };
    assert!(depth <= proof_len);
    let input =
        mpt_direct_input(val.to_vec(), proof, root, key, idx > 199, depth, 32, Some(key_byte_len)); // depth = max_depth
    let params = default_params();
    let k = params.base.k as u32;
    let circuit = test_mpt_circuit::<Fr>(CircuitBuilderStage::Mock, params, input);
    let instances = circuit.instances();
    let prover = MockProver::run(k, &circuit, instances).unwrap();
    assert!(prover.verify().is_err(), "Should not verify")
    //Every outcome is valid except "Should not verify", in particular those that fail assertions elsewhere in the code
}

#[test_case(140, false, 1; "undercut by 1 inclusion")]
#[test_case(200, true, 1; "1 len inclusion")]
#[test_case(300, false, 1; "undercut by 1 noninclusion")]
#[test_case(350, true, 1; "1 len noninclusion")]
fn neg_invalid_max_key_byte_len(idx: usize, zero_start: bool, offset: usize) {
    let (mut trie, _) = gen_tx_tree(200, true, 48);
    let key = rlp::encode(&from_hex(&format!("{idx:x}"))).to_vec();
    let val = [
        0x43, 0x52, 0x59, 0x50, 0x54, 0x4f, 0x50, 0x55, 0x4e, 0x4b, 0x53, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x16,
    ];
    let root = trie.root().unwrap();
    let key_byte_len = key.len();
    let proof = trie.get_proof(&key).unwrap();
    let len = if zero_start { offset } else { key_byte_len - offset };
    assert!(len < key_byte_len);
    let input =
        mpt_direct_input(val.to_vec(), proof, root, key, idx > 199, 6, len, Some(key_byte_len)); // depth = max_depth
    let params = default_params();
    let k = params.base.k as u32;
    let circuit = test_mpt_circuit::<Fr>(CircuitBuilderStage::Mock, params, input);
    let instance = circuit.instances();
    let prover = MockProver::run(k, &circuit, instance).unwrap();
    assert!(prover.verify().is_err(), "Should not verify");
}

#[test_case(140, false, 1; "undercut by 1 inclusion")]
#[test_case(120, true , 1; "over by 1 inclusion")]
#[test_case(340, false, 1; "undercut by 1 noninclusion")]
#[test_case(320, true , 1; "over by 1 noninclusion")]
fn neg_invalid_key_byte_len(idx: usize, pos: bool, offset: usize) {
    let (mut trie, _) = gen_tx_tree(200, true, 48);
    let key = rlp::encode(&from_hex(&format!("{idx:x}"))).to_vec();
    let val = [
        0x43, 0x52, 0x59, 0x50, 0x54, 0x4f, 0x50, 0x55, 0x4e, 0x4b, 0x53, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let root = trie.root().unwrap();
    let key_byte_len = key.len();
    let proof = trie.get_proof(&key).unwrap();
    let len = if pos { key_byte_len + offset } else { key_byte_len - offset };
    let input = mpt_direct_input(val.to_vec(), proof, root, key, idx > 199, 6, 32, Some(len)); // depth = max_depth
    let params = default_params();
    let k = params.base.k as u32;
    let circuit = test_mpt_circuit::<Fr>(CircuitBuilderStage::Mock, params, input);
    let instance = circuit.instances();
    let prover = MockProver::run(k, &circuit, instance).unwrap();
    assert!(prover.verify().is_err(), "should not verify");
}

#[test_case(140, false, 1; "undercut by 1 inclusion")]
#[test_case(120, true , 1; "over by 1 inclusion")]
#[test_case(340, false, 1; "undercut by 1 noninclusion")]
#[test_case(320, true , 1; "over by 1 noninclusion")]
fn neg_invalid_max_key_byte_len_fixed(idx: usize, pos: bool, offset: usize) {
    let (mut trie, _) = gen_tx_tree(200, true, 48);
    let key = rlp::encode(&from_hex(&format!("{idx:x}"))).to_vec();
    let val = [
        0x43, 0x52, 0x59, 0x50, 0x54, 0x4f, 0x50, 0x55, 0x4e, 0x4b, 0x53, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x16,
    ];
    let root = trie.root().unwrap();
    let key_byte_len = key.len();
    let proof = trie.get_proof(&key).unwrap();
    let len = if pos { key_byte_len + offset } else { key_byte_len - offset };
    let input = mpt_direct_input(val.to_vec(), proof, root, key, idx > 199, 6, len, None);
    let params = default_params();
    let k = params.base.k as u32;
    let circuit = test_mpt_circuit::<Fr>(CircuitBuilderStage::Mock, params, input);
    let instance = circuit.instances();
    let prover = MockProver::run(k, &circuit, instance).unwrap();
    assert!(prover.verify().is_err(), "should not verify");
}

#[test_case(0; "empty tree, loose")]
#[test_case(1; "empty tree, tight")]
#[test_case(2; "empty tree, fixed")]
fn pos_empty_tree_noninclusion(case_type: usize) {
    let (mut trie, _) = gen_tx_tree(0, true, 48);
    let root = trie.root().unwrap();
    let key = [0; 32].to_vec();
    let val = [0x0].to_vec();
    println!("{root:02x?}");
    assert!(verify_key_val(&trie, key, val, root, true, false, None, case_type));
}

#[test_case(200, 0, 300; "empty proof, loose noninclusion")]
#[test_case(200, 1, 300; "empty proof, tight noninclusion")]
#[test_case(200, 2, 300; "empty proof, fixed noninclusion")]
fn neg_nonempty_tree_empty_proof(num_keys: usize, case_type: usize, idx: usize) {
    let (mut trie, vals) = gen_tx_tree(num_keys, true, 48);
    let root = trie.root().unwrap();
    let key = rlp::encode(&from_hex(&format!("{idx:x}"))).to_vec();
    let inpval = if idx > 199 { [0x0].to_vec() } else { vals[idx].clone() };
    let input = if case_type == 0 {
        mpt_direct_input(
            inpval,
            [].to_vec(),
            root,
            key.clone(),
            idx >= num_keys,
            6,
            32,
            Some(key.len()),
        )
    } else if case_type == 1 {
        mpt_direct_input(
            inpval,
            [].to_vec(),
            root,
            key.clone(),
            idx >= num_keys,
            1,
            key.len(),
            Some(key.len()),
        )
    } else {
        mpt_direct_input(
            inpval,
            [].to_vec(),
            root,
            key.clone(),
            idx >= num_keys,
            6,
            key.len(),
            None,
        )
    };
    let params = default_params();
    let k = params.base.k as u32;
    let circuit = test_mpt_circuit::<Fr>(CircuitBuilderStage::Mock, params, input);
    let instance = circuit.instances();
    let prover = MockProver::run(k, &circuit, instance).unwrap();
    assert!(prover.verify().is_err(), "should not verify");
}

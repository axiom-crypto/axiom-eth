use crate::{
    solidity::tests::{mapping::*, utils::MappingTest},
    utils::eth_circuit::EthCircuitImpl,
};
use ethers_core::{types::H256, utils::keccak256};
use halo2_base::{
    gates::circuit::CircuitBuilderStage,
    halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
        plonk::Circuit,
    },
};
use proptest::{collection::vec, prelude::*, sample::select};
use std::marker::PhantomData;

prop_compose! {
    pub fn rand_hex_string(max: usize)(val in vec(any::<u8>(), max)) -> Vec<u8> { val }
}

prop_compose! {
    // We assume key is of integer type so we left pad with 0s. Note bytes20 would need to be right padded with 0s
    pub fn rand_mapping_test(max: usize)
    (key in rand_hex_string(max), mapping_slot in rand_hex_string(32)) -> MappingTest<Fr> {
        let mapping_slot = [vec![0; 32 - mapping_slot.len()], mapping_slot.clone()].concat();
        let mslot = H256::from_slice(&mapping_slot.clone());
        assert!(key.len() <= 32);
        let padded_key = [vec![0; 32 - key.len()], key.clone()].concat();
        let ground_truth_concat_key = [padded_key.as_slice(), mslot.as_bytes()].concat();
        debug_assert_eq!(ground_truth_concat_key.len(), padded_key.len() + 32);
        let ground_truth_slot = keccak256(ground_truth_concat_key.clone()).to_vec();

        MappingTest {
            key,
            var_len: None,
            max_var_len: None,
            mapping_slot,
            ground_truth_concat_key,
            ground_truth_slot,
            _marker: PhantomData
        }
    }
}

prop_compose! {
    pub fn rand_var_len_mapping_test(max_len: usize)
    (var_len in 1..=max_len)
    (mut key in rand_hex_string(var_len), mapping_slot in rand_hex_string(32), var_len in Just(var_len), max_len in Just(max_len)) -> MappingTest<Fr> {
        assert_eq!(key.len(), var_len);
        let slot = [vec![0; 32 - mapping_slot.len()], mapping_slot.clone()].concat();
        let m_slot = H256::from_slice(&slot);
        let mut ground_truth_concat_key = [key.as_slice(), m_slot.as_bytes()].as_slice().concat();
        let ground_truth_slot = keccak256(ground_truth_concat_key.clone()).to_vec();
        ground_truth_concat_key.resize(max_len + 32, 0);
        key.resize(max_len, 0);
        MappingTest {
            key,
            var_len: Some(var_len),
            max_var_len: Some(max_len),
            mapping_slot,
            ground_truth_concat_key,
            ground_truth_slot,
            _marker: PhantomData
        }
    }
}

prop_compose! {
    pub fn rand_byte_sized_mapping_test()
    (size in select(vec![1,2,4,8,16,32]))
    (key in rand_hex_string(size), mapping_slot in rand_hex_string(32)) -> MappingTest<Fr> {
        let slot = [vec![0; 32 - mapping_slot.len()], mapping_slot.clone()].concat();
        let mslot = H256::from_slice(&slot.clone());
        let padded_key = [vec![0; 32 - key.len()], key.clone()].concat();
        let ground_truth_concat_key = [padded_key.as_slice(), mslot.as_bytes()].concat();
        debug_assert!(ground_truth_concat_key.len() == 64);
        let ground_truth_slot = keccak256(ground_truth_concat_key.clone()).to_vec();
        MappingTest {
            key,
            var_len: None,
            max_var_len: None,
            mapping_slot,
            ground_truth_concat_key,
            ground_truth_slot,
            _marker: PhantomData
        }
    }
}

pub fn prop_mock_prover_satisfied(
    (circuit, instance): (EthCircuitImpl<Fr, MappingTest<Fr>>, Vec<Fr>),
) -> Result<(), Vec<VerifyFailure>> {
    let k = circuit.params().k() as u32;
    MockProver::run(k, &circuit, vec![instance]).unwrap().verify()
}

proptest! {

    #[test]
    #[ignore]
    fn prop_test_pos_rand_bytes32_key(input in rand_mapping_test(32)) {
        prop_mock_prover_satisfied(mapping_circuit(CircuitBuilderStage::Mock, input,None,  None)).unwrap();
    }

    #[test]
    #[ignore]
    fn prop_test_pos_rand_address_key(input in rand_mapping_test(20)) {
        prop_mock_prover_satisfied(mapping_circuit(CircuitBuilderStage::Mock, input,None,  None)).unwrap();
    }

    #[test]
    #[ignore]
    fn prop_test_pos_rand_uint_key(input in rand_byte_sized_mapping_test()) {
        prop_mock_prover_satisfied(mapping_circuit(CircuitBuilderStage::Mock, input, None, None)).unwrap();
    }

    #[test]
    #[ignore]
    fn prop_test_pos_rand_dynamic_array_key(input in rand_var_len_mapping_test(36)) {
        prop_mock_prover_satisfied(mapping_circuit(CircuitBuilderStage::Mock, input, None, None)).unwrap();
    }
}

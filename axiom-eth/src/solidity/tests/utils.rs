use crate::Field;
use ethers_core::{types::H256, utils::keccak256};
use halo2_base::{
    halo2_proofs::halo2curves::bn256::Fr,
    safe_types::{SafeBytes32, SafeTypeChip},
    AssignedValue, Context,
};
use hex::FromHex;
use itertools::Itertools;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{iter, marker::PhantomData, path::Path};

use crate::{
    solidity::types::SolidityType, utils::eth_circuit::EthCircuitParams,
    utils::unsafe_bytes_to_assigned,
};

pub const TEST_BLOCK_NUM: u32 = 17595887;

//Mainnet Contract Address
pub const WETH_MAINNET_ADDR: &str = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
pub const CRYPTOPUNKS_MAINNET_ADDR: &str = "0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb";
pub const UNI_V3_FACTORY_MAINNET_ADDR: &str = "0x1f98431c8ad98523631ae4a59f267346ea31f984";
pub const UNISOCKS_ERC20_MAINNET_ADDR: &str = "0x23b608675a2b2fb1890d3abbd85c5775c51691d5";
pub const UNISOCKS_ERC721_MAINNET_ADDR: &str = "0x65770b5283117639760bea3f867b69b3697a91dd";

//Json Paths
pub const UNI_V3_ADDR_ADDR_PATH: &str = "data/mappings/uni_v3_factory_get_pool_addr_addr.json";
pub const UNI_V3_ADDR_UINT_PATH: &str = "data/mappings/uni_v3_factory_get_pool_addr_uint.json";
pub const UNI_V3_UINT_ADDR_PATH: &str = "data/mappings/uni_v3_factory_get_pool_uint_addr.json";
pub const UNI_V3_FAKE_PATH: &str = "data/mappings/uni_v3_factory_fake.json";

pub const UNISOCKS_ERC20_BALANCE_OF_PATH: &str =
    "data/mappings/unisocks_erc20_balance_of_addr_uint.json";
pub const UNISOCKS_ERC721_BALANCE_OF_PATH: &str =
    "data/mappings/unisocks_erc721_balance_of_addr_uint.json";
pub const CRYPTOPUNKS_BALANCE_OF_PATH: &str = "data/mappings/cryptopunks_balance_of_addr_uint.json";

pub const WETH_BALANCE_OF_ADDRESS_PATH: &str = "data/mappings/weth_balance_of_addr_uint.json";
pub const WETH_BALANCE_OF_BYTES32_PATH: &str = "data/mappings/weth_balance_of_bytes32_uint.json";

pub const WETH_ALLOWANCE_ADDR_ADDR_PATH: &str = "data/mappings/weth_allowance_addr_addr.json";
pub const WETH_ALLOWANCE_ADDR_UINT_PATH: &str = "data/mappings/weth_allowance_addr_uint.json";

pub const ANVIL_BALANCE_OF_PATH: &str = "data/mappings/anvil_dynamic_uint.json";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MappingTest<F> {
    pub key: Vec<u8>,
    pub var_len: Option<usize>,
    pub max_var_len: Option<usize>,
    pub mapping_slot: Vec<u8>,
    pub ground_truth_concat_key: Vec<u8>,
    pub ground_truth_slot: Vec<u8>,
    pub _marker: PhantomData<F>,
}

#[derive(Debug, Clone)]
pub struct AssignedMappingTest<F: Field> {
    pub key: SolidityType<F>,
    pub var_len: Option<usize>,
    pub max_var_len: Option<usize>,
    pub mapping_slot: SafeBytes32<F>,
}

impl<F: Field> MappingTest<F> {
    pub fn assign(&self, ctx: &mut Context<F>, safe: &SafeTypeChip<F>) -> AssignedMappingTest<F> {
        let key_bytes = unsafe_bytes_to_assigned(ctx, &self.key);
        // Determine value or nonvalue based on Option of var_len
        let key = get_test_key(&self.var_len, &self.max_var_len, safe, ctx, key_bytes);

        let mapping_slot_bytes = unsafe_bytes_to_assigned(ctx, &self.mapping_slot);
        let mapping_slot = safe.raw_bytes_to::<1, 256>(ctx, mapping_slot_bytes);

        AssignedMappingTest {
            key,
            var_len: self.var_len,
            max_var_len: self.max_var_len,
            mapping_slot,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BenchParams(pub EthCircuitParams, pub usize); // (params, num_slots)
/// (byte len, optional max byte len if non-value type)
pub type MappingTestData = (usize, Option<usize>);

/// Inputs a mapping test from a json file
pub fn mapping_test_input(path: impl AsRef<Path>) -> MappingTest<Fr> {
    let mapping_test_str = std::fs::read_to_string(path).unwrap();
    let mapping_test: serde_json::Value = serde_json::from_str(mapping_test_str.as_str()).unwrap();

    let key_bytes_str: String = serde_json::from_value(mapping_test["key"].clone()).unwrap();
    let key = Vec::from_hex(key_bytes_str).unwrap();

    let var_len_str: String = serde_json::from_value(mapping_test["var_len"].clone()).unwrap();
    let var_len = match var_len_str.is_empty() {
        true => None,
        false => Some(var_len_str.parse::<usize>().unwrap()),
    };

    let max_var_len_str: String =
        serde_json::from_value(mapping_test["max_var_len"].clone()).unwrap();
    let max_var_len = match max_var_len_str.is_empty() {
        true => None,
        false => Some(max_var_len_str.parse::<usize>().unwrap()),
    };

    let mapping_slot_str: String =
        serde_json::from_value(mapping_test["mapping_slot"].clone()).unwrap();
    let mapping_slot = Vec::from_hex(mapping_slot_str).unwrap();

    let ground_truth_concat_key_str: String =
        serde_json::from_value(mapping_test["ground_truth_concat_key"].clone()).unwrap();
    let ground_truth_concat_key = Vec::from_hex(ground_truth_concat_key_str).unwrap();

    let ground_truth_slot_str: String =
        serde_json::from_value(mapping_test["ground_truth_slot"].clone()).unwrap();
    let ground_truth_slot = Vec::from_hex(ground_truth_slot_str).unwrap();

    MappingTest {
        key,
        var_len,
        max_var_len,
        mapping_slot,
        ground_truth_concat_key,
        ground_truth_slot,
        _marker: PhantomData,
    }
}

pub fn get_test_key<F: Field>(
    var_len: &Option<usize>,
    max_var_len: &Option<usize>,
    safe: &SafeTypeChip<F>,
    ctx: &mut Context<F>,
    test_key_bytes: Vec<AssignedValue<F>>,
) -> SolidityType<F> {
    match var_len {
        Some(var_len) => SolidityType::NonValue({
            let max_var_len = max_var_len.unwrap_or(test_key_bytes.len());
            let var_len = ctx.load_witness(F::from(*var_len as u64));
            safe.raw_to_var_len_bytes_vec(ctx, test_key_bytes, var_len, max_var_len)
        }),
        None => {
            let test_key_bytes = iter::repeat(ctx.load_zero())
                .take(32 - test_key_bytes.len())
                .chain(test_key_bytes)
                .collect_vec();
            SolidityType::Value(safe.raw_bytes_to::<1, 256>(ctx, test_key_bytes))
        }
    }
}

pub fn rand_hex_array(max: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0; max];
    rng.fill_bytes(&mut bytes);
    bytes
}

pub fn rand_mapping_data((len, max_len): (usize, Option<usize>)) -> MappingTest<Fr> {
    let key = rand_hex_array(len);
    let mapping_slot = rand_hex_array(32);
    let m_slot = H256::from_slice(&mapping_slot.clone());

    let (key, ground_truth_slot, ground_truth_concat_key, var_len, max_var_len) = match max_len {
        Some(max_len) => {
            let mut ground_truth_concat_key = [key.as_slice(), m_slot.as_bytes()].concat();
            let ground_truth_slot = keccak256(&ground_truth_concat_key[..len + 32]).to_vec();
            ground_truth_concat_key.resize(max_len + 32, 0);
            let key =
                key.iter().chain(iter::repeat(&0)).take(max_len).cloned().collect::<Vec<u8>>();
            (key, ground_truth_slot, ground_truth_concat_key, Some(len), Some(max_len))
        }
        None => {
            let padded_key = [vec![0; 32 - key.len()], key.clone()].concat();
            let ground_truth_concat_key = [padded_key.as_slice(), m_slot.as_bytes()].concat();
            debug_assert!(ground_truth_concat_key.len() == 64);
            let ground_truth_slot = keccak256(ground_truth_concat_key.clone()).to_vec();
            (key, ground_truth_slot, ground_truth_concat_key, None, None)
        }
    };

    MappingTest {
        key,
        var_len,
        max_var_len,
        mapping_slot,
        ground_truth_concat_key,
        ground_truth_slot,
        _marker: PhantomData,
    }
}

pub fn rand_nested_mapping_data(tests: Vec<(usize, Option<usize>)>) -> Vec<MappingTest<Fr>> {
    let mut slot = rand_hex_array(32);

    tests.into_iter().fold(Vec::new(), |mut acc, (len, max_len)| {
        let key = rand_hex_array(len);
        let mapping_slot = slot.to_vec();
        let m_slot = H256::from_slice(&mapping_slot.clone());

        let (key, ground_truth_slot, ground_truth_concat_key, var_len, max_var_len) = match max_len
        {
            Some(max_len) => {
                let ground_truth_concat_key =
                    [key.as_slice(), m_slot.as_bytes(), vec![0; max_len - len].as_slice()].concat();
                let key =
                    key.iter().chain(iter::repeat(&0)).take(max_len).cloned().collect::<Vec<u8>>();
                let ground_truth_slot = keccak256(&ground_truth_concat_key[..len + 32]).to_vec();
                (key, ground_truth_slot, ground_truth_concat_key, Some(len), Some(max_len))
            }
            None => {
                let padded_key = [vec![0; 32 - key.len()], key.clone()].concat();
                let ground_truth_concat_key = [padded_key.as_slice(), m_slot.as_bytes()].concat();
                debug_assert!(ground_truth_concat_key.len() == 64);
                let ground_truth_slot = keccak256(ground_truth_concat_key.clone()).to_vec();
                (key, ground_truth_slot, ground_truth_concat_key, None, None)
            }
        };

        acc.push(MappingTest {
            key,
            var_len,
            max_var_len,
            mapping_slot,
            ground_truth_concat_key,
            ground_truth_slot: ground_truth_slot.clone(),
            _marker: PhantomData,
        });
        slot = ground_truth_slot;
        acc
    })
}

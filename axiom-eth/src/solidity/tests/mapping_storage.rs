use std::str::FromStr;

use test_case::test_case;

use crate::rlc::{circuit::RlcCircuitParams, tests::get_rlc_params};

use super::*;
const MAX_MAPPING_KEY_BYTE_LEN: usize = 32;

//======== Sourced Data Tests =========
#[test_case(vec![CRYPTOPUNKS_BALANCE_OF_PATH], CRYPTOPUNKS_MAINNET_ADDR; "cryptopunks_balance_of")]
#[test_case(vec![UNISOCKS_ERC20_BALANCE_OF_PATH], UNISOCKS_ERC20_MAINNET_ADDR; "unisocks_erc20_balance_of")]
#[test_case(vec![UNISOCKS_ERC721_BALANCE_OF_PATH], UNISOCKS_ERC721_MAINNET_ADDR; "unisocks_erc721_balance_of")]
#[test_case(vec![WETH_BALANCE_OF_ADDRESS_PATH], WETH_MAINNET_ADDR; "weth_balance_of")]
#[test_case(vec![WETH_ALLOWANCE_ADDR_ADDR_PATH, WETH_ALLOWANCE_ADDR_UINT_PATH], WETH_MAINNET_ADDR; "weth_allowance_double_mapping")]
#[test_case(vec![UNI_V3_ADDR_ADDR_PATH, UNI_V3_ADDR_UINT_PATH, UNI_V3_UINT_ADDR_PATH], UNI_V3_FACTORY_MAINNET_ADDR; "uni_v3_triple_mapping")]
pub fn test_mock_mapping_storage_pos(paths: Vec<&str>, addr: &str) {
    let mapping_data =
        paths.into_iter().map(|path| mapping_test_input(Path::new(path))).collect_vec();
    let slot = vec![H256::from_slice(&mapping_data.last().unwrap().ground_truth_slot)];
    let storage_pf = get_block_storage_input(
        &setup_provider(Chain::Mainnet),
        TEST_BLOCK_NUM,
        H160::from_str(addr).unwrap(),
        slot,
        8,
        8,
    )
    .storage;
    let circuit =
        mapping_storage_circuit(CircuitBuilderStage::Mock, mapping_data, storage_pf, None, None);
    let k = circuit.params().k() as u32;
    let instances = circuit.instances();
    MockProver::run(k, &circuit, instances).unwrap().assert_satisfied();
}

#[test_case(vec![WETH_BALANCE_OF_ADDRESS_PATH], WETH_MAINNET_ADDR, H256::zero())]
#[test_case(vec![WETH_ALLOWANCE_ADDR_ADDR_PATH, WETH_ALLOWANCE_ADDR_UINT_PATH], WETH_MAINNET_ADDR, H256::zero())]
#[test_case(vec![UNI_V3_ADDR_ADDR_PATH, UNI_V3_ADDR_UINT_PATH, UNI_V3_UINT_ADDR_PATH], UNI_V3_FACTORY_MAINNET_ADDR, H256::zero())]
pub fn test_mock_mapping_storage_neg(paths: Vec<&str>, addr: &str, invalid_slot: H256) {
    let mapping_data =
        paths.into_iter().map(|path| mapping_test_input(Path::new(path))).collect_vec();
    let invalid_storage_pf = get_block_storage_input(
        &setup_provider(Chain::Mainnet),
        TEST_BLOCK_NUM,
        H160::from_str(addr).unwrap(),
        vec![invalid_slot],
        8,
        8,
    )
    .storage;
    let circuit = mapping_storage_circuit(
        CircuitBuilderStage::Mock,
        mapping_data,
        invalid_storage_pf,
        None,
        None,
    );
    let k = circuit.params().k() as u32;
    let instances = circuit.instances();
    assert!(MockProver::run(k, &circuit, instances).unwrap().verify().is_err());
}

#[derive(Clone)]
struct MappingStorageTest<F> {
    test_data: Vec<MappingTest<F>>,
    proof: EthStorageInput,
}

impl<F: Field> EthCircuitInstructions<F> for MappingStorageTest<F> {
    type FirstPhasePayload = (NestedMappingWitness<F>, EthStorageWitness<F>);
    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
    ) -> Self::FirstPhasePayload {
        let chip = SolidityChip::new(mpt, MAX_NESTING, MAX_MAPPING_KEY_BYTE_LEN);
        let safe = SafeTypeChip::new(mpt.range());
        let ctx = builder.base.main(FIRST_PHASE);
        let inputs = self.test_data.iter().map(|data| data.assign(ctx, &safe)).collect_vec();
        let mapping_slot = inputs[0].mapping_slot.clone();
        let proof = self.proof.storage_pfs[0].2.clone().assign(ctx);
        let mut keys = inputs.iter().map(|input| input.key.clone()).collect_vec();
        let nestings = ctx.load_witness(F::from(inputs.len() as u64));
        keys.resize(MAX_NESTING, keys[0].clone());
        chip.verify_mapping_storage_phase0::<{ MAX_NESTING }>(
            ctx,
            mapping_slot,
            keys.try_into().unwrap(),
            nestings,
            proof,
        )
    }
    fn virtual_assign_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
        (nested_witness, storage_witness): Self::FirstPhasePayload,
    ) {
        let chip = SolidityChip::new(mpt, MAX_NESTING, MAX_MAPPING_KEY_BYTE_LEN);
        let (ctx_gate, ctx_rlc) = builder.rlc_ctx_pair();
        chip.verify_mapping_storage_phase1((ctx_gate, ctx_rlc), nested_witness, storage_witness);
    }
}

fn mapping_storage_circuit<F: Field>(
    stage: CircuitBuilderStage,
    test_data: Vec<MappingTest<F>>,
    proof: EthStorageInput,
    params: Option<RlcCircuitParams>,
    break_points: Option<RlcThreadBreakPoints>,
) -> EthCircuitImpl<F, MappingStorageTest<F>> {
    let params = if let Some(params) = params {
        params
    } else {
        get_rlc_params("configs/tests/storage_mapping.json")
    };
    let input = MappingStorageTest { test_data, proof };

    let mut circuit = create_circuit(stage, params, input);
    circuit.mock_fulfill_keccak_promises(None);
    circuit.calculate_params();
    if let Some(bp) = break_points {
        circuit.set_break_points(bp);
    }
    circuit
}

// Skipping prover tests because it is combination of mapping slot computation and storage proof

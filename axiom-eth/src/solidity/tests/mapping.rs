use test_case::test_case;
use test_log::test;

use crate::{
    rlc::{circuit::RlcCircuitParams, tests::get_rlc_params},
    solidity::types::MappingWitness,
};

use super::*;

//======== Mock Prover Tests =========
#[test_case(ANVIL_BALANCE_OF_PATH; "anvil_balance_of")]
#[test_case(WETH_BALANCE_OF_ADDRESS_PATH; "weth_balance_of_address")]
#[test_case(WETH_BALANCE_OF_BYTES32_PATH; "weth_balance_of_bytes32")]
pub fn test_mock_mapping_pos_from_json(json_path: &str) {
    let data = mapping_test_input(Path::new(json_path));
    let (circuit, instance) = mapping_circuit(CircuitBuilderStage::Mock, data, None, None);
    let k = circuit.params().k() as u32;
    MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied()
}

#[test_case((20, None); "address")]
#[test_case((1, None); "uint8")]
#[test_case((2, None); "uint16")]
#[test_case((4, None); "uint32")]
#[test_case((8, None); "uint64")]
#[test_case((16, None); "uint128")]
#[test_case((32, None); "uint256")]
#[test_case((0, Some(1)); "dynamic_var_len_0")]
#[test_case((1, Some(1)); "dynamic_var_len_1")]
pub fn test_mock_mapping_pos_random(data: MappingTestData) {
    let data = rand_mapping_data(data);
    let (circuit, instance) = mapping_circuit(CircuitBuilderStage::Mock, data, None, None);
    let k = circuit.params().k() as u32;
    MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied()
}

// Should panic from assert
#[test]
#[should_panic]
pub fn neg_mock_dynamic_var_len_equal_max_len() {
    let data = rand_mapping_data((2, Some(1)));
    let (circuit, instance) = mapping_circuit(CircuitBuilderStage::Mock, data, None, None);
    let k = circuit.params().k() as u32;
    assert!(MockProver::run(k, &circuit, vec![instance]).unwrap().verify().is_ok());
}

//======== Prover Tests =========
impl<F: Field> EthCircuitInstructions<F> for MappingTest<F> {
    type FirstPhasePayload = (MappingWitness<F>, usize);
    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
    ) -> Self::FirstPhasePayload {
        let max_key_byte_len = self.max_var_len.unwrap_or(32);
        let chip = SolidityChip::new(mpt, MAX_NESTING, max_key_byte_len);
        let safe = SafeTypeChip::new(mpt.range());
        let ctx = builder.base.main(FIRST_PHASE);
        let input = self.clone().assign(ctx, &safe);
        let witness = chip.slot_for_mapping_key_phase0(ctx, input.mapping_slot, input.key);

        let assigned_instances = witness.slot().as_ref().to_vec();
        builder.base.assigned_instances[0] = assigned_instances;
        (witness, max_key_byte_len)
    }
    fn virtual_assign_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
        (witness, max_key_byte_len): Self::FirstPhasePayload,
    ) {
        let chip = SolidityChip::new(mpt, MAX_NESTING, max_key_byte_len);
        let (ctx_gate, ctx_rlc) = builder.rlc_ctx_pair();
        chip.slot_for_mapping_key_phase1((ctx_gate, ctx_rlc), witness);
    }
}

pub fn mapping_circuit(
    stage: CircuitBuilderStage,
    test_data: MappingTest<Fr>,
    params: Option<RlcCircuitParams>,
    break_points: Option<RlcThreadBreakPoints>,
) -> (EthCircuitImpl<Fr, MappingTest<Fr>>, Vec<Fr>) {
    let instance_wo_commit =
        test_data.ground_truth_slot.iter().map(|x| Fr::from(*x as u64)).collect_vec();
    let mut params = if let Some(params) = params {
        params
    } else {
        get_rlc_params("configs/tests/storage_mapping.json")
    };
    params.base.num_instance_columns = 1;
    let mut circuit = create_circuit(stage, params, test_data);
    circuit.mock_fulfill_keccak_promises(None);
    if !stage.witness_gen_only() {
        circuit.calculate_params();
    }
    if let Some(bp) = break_points {
        circuit.set_break_points(bp);
    }
    let instances = circuit.instances();
    let mut instance = instances[0].clone();
    instance.pop().unwrap();
    assert_eq!(instance_wo_commit, instance);

    (circuit, instances[0].clone())
}

#[test_case((1, None), (1, None), true; "pos_prover_uint8")]
#[test_case((32, None), (32, None), true; "pos_prover_bytes32")]
#[test_case((1, Some(32)), (1, Some(32)), true; "pos_prover_dynamic_keys_same_var_len_and_max_len")]
#[test_case((1, Some(32)), (3, Some(32)), true; "pos_prover_dynamic_keys_diff_var_len_same_max_len")]
#[test_case((1, None), (2, None), false; "neg_prover_uint8_uint16")]
#[test_case((1, Some(32)), (1, Some(33)), false; "neg_dynamic_keys_diff_max_len")]
pub fn mapping_prover_satisfied(
    keygen_data: MappingTestData,
    proof_data: MappingTestData,
    expected: bool,
) {
    let (circuit, _) =
        mapping_circuit(CircuitBuilderStage::Keygen, rand_mapping_data(keygen_data), None, None);
    let bench_params = circuit.params().rlc;
    let k = bench_params.base.k as u32;
    let params = gen_srs(k);
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let break_points = circuit.break_points();

    let (circuit, instance) = mapping_circuit(
        CircuitBuilderStage::Prover,
        rand_mapping_data(proof_data),
        Some(bench_params),
        Some(break_points),
    );
    let proof = gen_proof_with_instances(&params, &pk, circuit, &[&instance]);
    check_proof_with_instances(&params, pk.get_vk(), &proof, &[&instance], expected);
}

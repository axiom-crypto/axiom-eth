use test_case::test_case;

use crate::rlc::{circuit::RlcCircuitParams, tests::get_rlc_params};

use super::*;

//======== Sourced Data Tests =========
#[test]
pub fn test_mock_weth_allowance() {
    let data = vec![
        mapping_test_input(Path::new(WETH_ALLOWANCE_ADDR_ADDR_PATH)),
        mapping_test_input(Path::new(WETH_ALLOWANCE_ADDR_UINT_PATH)),
    ];
    let (circuit, instance) = nested_mapping_circuit(CircuitBuilderStage::Mock, data, None, None);
    let k = circuit.params().k() as u32;
    MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied()
}

#[test]
pub fn test_mock_uni_v3_factory_get_pool() {
    let data = vec![
        mapping_test_input(Path::new(UNI_V3_ADDR_ADDR_PATH)),
        mapping_test_input(Path::new(UNI_V3_ADDR_UINT_PATH)),
        mapping_test_input(Path::new(UNI_V3_UINT_ADDR_PATH)),
    ];
    let (circuit, instance) = nested_mapping_circuit(CircuitBuilderStage::Mock, data, None, None);
    let k = circuit.params().k() as u32;
    MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied()
}

//======== Mock Prover Tests =========
#[test_case(vec![(32, None), (20, None)]; "double_mapping_test_bytes32_addr")]
#[test_case(vec![(1, None), (20, None), (32, None)]; "triple_mapping_test_uint8_addr_bytes32")]
#[test_case(vec![(1, Some(2)), (1, None), (20, None)]; "triple_mapping_test_dynamic_uint8_addr")]
#[test_case(vec![(1, None), (1, Some(32)), (20, None)]; "triple_mapping_test_uint8_dynamic_addr")]
#[test_case(vec![(1, None), (20, None), (1, Some(32))]; "triple_mapping_test_uint8_addr_dynamic")]
pub fn test_mock_nested_mapping_pos(data: Vec<MappingTestData>) {
    let data = rand_nested_mapping_data(data);
    let (circuit, instance) = nested_mapping_circuit(CircuitBuilderStage::Mock, data, None, None);
    let k = circuit.params().k() as u32;
    MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied()
}

//======== Prover Tests =========
#[derive(Clone)]
struct NestedMappingTest<F>(Vec<MappingTest<F>>);

impl<F: Field> EthCircuitInstructions<F> for NestedMappingTest<F> {
    type FirstPhasePayload = (NestedMappingWitness<F>, usize);
    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
    ) -> Self::FirstPhasePayload {
        let max_key_byte_len = self.0[0].max_var_len.unwrap_or(32);
        let chip = SolidityChip::new(mpt, MAX_NESTING, max_key_byte_len);
        let safe = SafeTypeChip::new(mpt.range());
        let ctx = builder.base.main(FIRST_PHASE);
        let inputs = self.0.iter().map(|data| data.assign(ctx, &safe)).collect_vec();
        let mapping_slot = inputs[0].mapping_slot.clone();
        let mut keys = inputs.iter().map(|input| input.key.clone()).collect_vec();
        let nestings = ctx.load_witness(F::from(keys.len() as u64));
        keys.resize(MAX_NESTING, keys[0].clone());
        let witness = chip.slot_for_nested_mapping_phase0::<{ MAX_NESTING }>(
            ctx,
            mapping_slot,
            keys.try_into().unwrap(),
            nestings,
        );
        builder.base.assigned_instances[0] = witness.slot.as_ref().to_vec();
        (witness, max_key_byte_len)
    }
    fn virtual_assign_phase1(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        mpt: &MPTChip<F>,
        (witness, max_key_byte_len): Self::FirstPhasePayload,
    ) {
        let chip = SolidityChip::new(mpt, MAX_NESTING, max_key_byte_len);
        chip.slot_for_nested_mapping_phase1(builder.rlc_ctx_pair(), witness);
    }
}

// re-use MappingTest struct for keys, but only use first mapping slot
fn nested_mapping_circuit(
    stage: CircuitBuilderStage,
    test_data: Vec<MappingTest<Fr>>,
    params: Option<RlcCircuitParams>,
    break_points: Option<RlcThreadBreakPoints>,
) -> (EthCircuitImpl<Fr, NestedMappingTest<Fr>>, Vec<Fr>) {
    let mut params = if let Some(params) = params {
        params
    } else {
        get_rlc_params("configs/tests/storage_mapping.json")
    };
    let instance_wo_commit = test_data
        .last()
        .unwrap()
        .ground_truth_slot
        .iter()
        .map(|x| Fr::from(*x as u64))
        .collect_vec();
    params.base.num_instance_columns = 1;
    let mut circuit = create_circuit(stage, params, NestedMappingTest(test_data));
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

#[test_case(vec![(20, None), (1, None), (32, None)], vec![(20, None), (1, None), (32, None)], true;
"pos_prover_triple_mapping_addr_uint8_bytes32")]
#[test_case(vec![(1, Some(2)), (20, None), (32, None)], vec![(1, Some(2)), (20, None), (32, None)], true;
"pos_prover_triple_mapping_dynamic_addr_bytes32")]
#[test_case(vec![(20, None), (1, Some(2)), (32, None)], vec![(20, None), (1, Some(2)), (32, None)], true;
"pos_prover_triple_mapping_addr_dynamic_bytes32")]
#[test_case(vec![(20, None), (32, None), (1, Some(2))], vec![(20, None), (32, None), (1, Some(2))], true;
"pos_prover_triple_mapping_addr_bytes32_dynamic")]
#[test_case(vec![(20, None), (1, None), (32, None)], vec![(20, None), (32, None), (1, None)], false;
"neg_prover_triple_mapping_addr_uint8_bytes32_to_address_bytes32_uint8")]
// #[test_case(vec![(20, None), (1, None), (32, None)], vec![(20, Some(21)), (1, None), (32, None)], false;
// "neg_prover_triple_mapping_addr_uint8_bytes32_to_dynamic_uint8_bytes32")] // catch_unwind not catching this, should panic
// #[test_case(vec![(20, None), (1, None), (32, None)], vec![(20, None), (1, Some(2)), (32, None)], false;
// "neg_prover_triple_mapping_addr_uint8_bytes32_to_addr_dynamic_uint8")] // catch_unwind not catching, should panic
// #[test_case(vec![(20, None), (1, None), (32, None)], vec![(20, None), (1, None), (32, Some(33))], false;
// "neg_prover_triple_mapping_addr_uint8_bytes32_to_addr_uint8_dynamic")] // catch_unwind not catching this, should panic
pub fn nested_mapping_prover_satisfied(
    keygen_input: Vec<MappingTestData>,
    proof_input: Vec<MappingTestData>,
    expected: bool,
) {
    let (circuit, _) = nested_mapping_circuit(
        CircuitBuilderStage::Keygen,
        rand_nested_mapping_data(keygen_input),
        None,
        None,
    );
    let bench_params = circuit.params().rlc;
    let k = bench_params.base.k as u32;

    let params = gen_srs(k);
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let break_points = circuit.break_points();

    let pf_instance = catch_unwind(|| {
        let (circuit, instance) = nested_mapping_circuit(
            CircuitBuilderStage::Prover,
            rand_nested_mapping_data(proof_input),
            Some(bench_params),
            Some(break_points),
        );
        let proof = gen_proof_with_instances(&params, &pk, circuit, &[&instance]);
        (proof, instance)
    });
    if let Ok((proof, instance)) = pf_instance {
        check_proof_with_instances(&params, pk.get_vk(), &proof, &[&instance], expected);
    } else {
        // On some bad inputs we have assert fails during witness generation
        assert!(!expected, "Runtime error in proof generation");
    }
}

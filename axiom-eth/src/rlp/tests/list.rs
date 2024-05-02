use super::*;
use test_log::test;

// Both positive and negative tests for RLP decoding a byte string
struct RlpListTest<F: ScalarField> {
    encoded: Vec<u8>,
    max_field_lens: Vec<usize>,
    is_var_len: bool,
    prank_idx: Option<usize>,
    prank_component: Option<usize>,
    _marker: PhantomData<F>,
}

impl<F: ScalarField> RlcCircuitInstructions<F> for RlpListTest<F> {
    type FirstPhasePayload = (RlpArrayWitness<F>, bool);

    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
    ) -> Self::FirstPhasePayload {
        let ctx = builder.base.main(0);
        let inputs = ctx.assign_witnesses(self.encoded.iter().map(|x| F::from(*x as u64)));
        let chip = RlpChip::new(range, None);
        let mut witness =
            chip.decompose_rlp_array_phase0(ctx, inputs, &self.max_field_lens, self.is_var_len);
        if let Some(prank_component) = self.prank_component {
            let (prank_len, prank_comp) = match prank_component {
                0 => (witness.rlp_len, &mut witness.rlp_array),
                1 => (witness.len_len, &mut witness.len_cells),
                2 => (
                    witness.field_witness[0].encoded_item_len,
                    &mut witness.field_witness[0].encoded_item,
                ),
                _ => (
                    witness.field_witness[0].encoded_item_len,
                    &mut witness.field_witness[0].encoded_item,
                ),
            };
            if let Some(prank_idx) = self.prank_idx {
                if prank_component < 3 && prank_idx < prank_comp.len() {
                    let prankval = range.gate().add(ctx, prank_comp[prank_idx], Constant(F::ONE));
                    prank_comp[prank_idx].debug_prank(ctx, *prankval.value());
                }
                let bad_idx = range.is_less_than_safe(ctx, prank_len, prank_idx as u64 + 1);
                let zero = ctx.load_zero();
                ctx.constrain_equal(&bad_idx, &zero);
            }
        }
        (witness, self.is_var_len)
    }

    fn virtual_assign_phase1(
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
        rlc: &RlcChip<F>,
        (witness, is_var_len): (RlpArrayWitness<F>, bool),
    ) {
        let chip = RlpChip::new(range, Some(rlc));
        let (ctx_gate, ctx_rlc) = builder.rlc_ctx_pair();
        chip.decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness, is_var_len);
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![vec![]]
    }
}

fn rlp_list_circuit<F: ScalarField>(
    stage: CircuitBuilderStage,
    encoded: Vec<u8>,
    max_field_lens: &[usize],
    is_var_len: bool,
    prank_idx: Option<usize>,
    prank_component: Option<usize>,
) -> RlcCircuit<F, RlpListTest<F>> {
    let input = RlpListTest {
        encoded,
        max_field_lens: max_field_lens.to_vec(),
        is_var_len,
        prank_idx,
        prank_component,
        _marker: PhantomData,
    };
    let mut builder = RlcCircuitBuilder::from_stage(stage, 10).use_k(DEGREE as usize);
    builder.base.set_lookup_bits(8);
    let circuit = RlcExecutor::new(builder, input);
    if !stage.witness_gen_only() {
        circuit.0.calculate_params(Some(9));
    }
    circuit
}

#[test]
pub fn test_mock_rlp_array() {
    let k = DEGREE;
    // the list [ "cat", "dog" ] = [ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' ]
    let cat_dog: Vec<u8> = vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];
    // the empty list = [ 0xc0 ]
    let empty_list: Vec<u8> = vec![0xc0];
    let input_bytes: Vec<u8> = Vec::from_hex("f8408d123000000000000000000000028824232222222222238b32222222222222222412528a04233333333333332322912323333333333333333333333333333333000000").unwrap();

    for mut test_input in [cat_dog, empty_list, input_bytes] {
        test_input.resize(69, 0);
        let circuit = rlp_list_circuit::<Fr>(
            CircuitBuilderStage::Mock,
            test_input,
            &[15, 9, 11, 10, 17],
            true,
            None,
            None,
        );
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    }
}

#[test]
pub fn prank_test_mock_rlp_array() {
    let k = DEGREE;
    // the list [ "cat", "dog" ] = [ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' ]
    let cat_dog: Vec<u8> = vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];
    // the empty list = [ 0xc0 ]
    let empty_list: Vec<u8> = vec![0xc0];
    let input_bytes: Vec<u8> = Vec::from_hex("f8408d123000000000000000000000028824232222222222238b32222222222222222412528a04233333333333332322912323333333333333333333333333333333000000").unwrap();

    for mut test_input in [cat_dog, empty_list, input_bytes] {
        let prank_lens = [test_input.len(), 3, test_input.len()];
        for (j, prank_len) in prank_lens.into_iter().enumerate() {
            test_input.resize(69, 0);
            for i in 0..prank_len {
                let circuit = rlp_list_circuit::<Fr>(
                    CircuitBuilderStage::Mock,
                    test_input.clone(),
                    &[15, 9, 11, 10, 17],
                    true,
                    Some(i),
                    Some(j),
                );
                let prover = MockProver::run(k, &circuit, vec![]).unwrap();
                assert!(prover.verify().is_err(), "Unconstrained at {i}. Should not have verified");
            }
        }
    }
}

#[test]
fn test_list_len_not_big_fail() {
    let k = DEGREE;
    // the list [ "cat", "dog" ] = [ 0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g' ]
    // try to do RLP encoding where length is_big = true (even though it's not)
    // 0x08 is the length of the payload
    let mut attack: Vec<u8> = vec![0xf8, 0x08, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];
    attack.resize(69, 0);
    let circuit = rlp_list_circuit::<Fr>(
        CircuitBuilderStage::Mock,
        attack,
        &[15, 9, 11, 10, 17],
        true,
        None,
        None,
    );
    assert!(MockProver::run(k, &circuit, vec![]).unwrap().verify().is_err());
}

#[test]
fn test_list_len_leading_zeros_fail() {
    let k = DEGREE;
    // original:
    // let input_bytes: Vec<u8> = Vec::from_hex("f8408d123000000000000000000000028824232222222222238b32222222222222222412528a04233333333333332322912323333333333333333333333333333333000000").unwrap();
    let mut attack: Vec<u8> = Vec::from_hex("f900408d123000000000000000000000028824232222222222238b32222222222222222412528a04233333333333332322912323333333333333333333333333333333000000").unwrap();
    attack.resize(310, 0);
    let circuit = rlp_list_circuit::<Fr>(
        CircuitBuilderStage::Mock,
        attack,
        &[256, 9, 11, 10, 17], // make max payload length > 256 so we allow 2 bytes for len_len
        true,
        None,
        None,
    );
    assert!(MockProver::run(k, &circuit, vec![]).unwrap().verify().is_err());
}

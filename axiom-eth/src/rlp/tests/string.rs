use crate::rlp::types::RlpFieldWitness;

use super::*;
use test_case::test_case;

// Both positive and negative tests for RLP decoding a byte string
struct RlpStringTest<F: ScalarField> {
    encoded: Vec<u8>,
    max_len: usize,
    prank_idx: Option<usize>,
    prank_component: Option<usize>,
    _marker: PhantomData<F>,
}

impl<F: ScalarField> RlcCircuitInstructions<F> for RlpStringTest<F> {
    type FirstPhasePayload = RlpFieldWitness<F>;
    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
    ) -> Self::FirstPhasePayload {
        let ctx = builder.base.main(0);
        let inputs = ctx.assign_witnesses(self.encoded.iter().map(|x| F::from(*x as u64)));
        let chip = RlpChip::new(range, None);
        let mut witness = chip.decompose_rlp_field_phase0(ctx, inputs, self.max_len);
        // pranking for negative tests
        if let Some(prank_component) = self.prank_component {
            let (prank_comp, mut prank_len) = match prank_component {
                0 => (&mut witness.encoded_item, &witness.encoded_item_len),
                1 => (&mut witness.len_cells, &witness.len_len),
                2 => (&mut witness.field_cells, &witness.field_len),
                _ => (&mut witness.field_cells, &witness.field_len),
            };
            if let Some(prank_idx) = self.prank_idx {
                if prank_component < 3 {
                    if prank_idx < prank_comp.len() {
                        let prankval = *prank_comp[prank_idx].value() + F::ONE;
                        prank_comp[prank_idx].debug_prank(ctx, prankval);
                    }
                } else {
                    prank_len = &witness.prefix_len;
                    if prank_idx == 0 {
                        let prankval = *prank_comp[prank_idx].value() + F::ONE;
                        witness.prefix.debug_prank(ctx, prankval);
                    }
                }
                let bad_idx = range.is_less_than_safe(ctx, *prank_len, prank_idx as u64 + 1);
                println!("{:?}", *prank_len);
                println!("{:?}", prank_idx);
                let zero = ctx.load_zero();
                ctx.constrain_equal(&bad_idx, &zero);
            }
        }
        witness
    }
    fn virtual_assign_phase1(
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
        rlc: &RlcChip<F>,
        witness: Self::FirstPhasePayload,
    ) {
        let chip = RlpChip::new(range, Some(rlc));
        let (ctx_gate, ctx_rlc) = builder.rlc_ctx_pair();
        chip.decompose_rlp_field_phase1((ctx_gate, ctx_rlc), witness);
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![vec![]]
    }
}

fn rlp_string_circuit<F: ScalarField>(
    stage: CircuitBuilderStage,
    encoded: Vec<u8>,
    max_len: usize,
    prank_idx: Option<usize>,
    prank_component: Option<usize>,
) -> RlcCircuit<F, RlpStringTest<F>> {
    let input =
        RlpStringTest { encoded, max_len, prank_idx, prank_component, _marker: PhantomData };
    let mut builder = RlcCircuitBuilder::from_stage(stage, 6).use_k(DEGREE as usize);
    builder.base.set_lookup_bits(8);
    let circuit = RlcExecutor::new(builder, input);
    // auto-configure circuit if not in prover mode for convenience
    if !stage.witness_gen_only() {
        circuit.0.calculate_params(Some(9));
    }
    circuit
}

#[test_case(Vec::from_hex("a012341234123412341234123412341234123412341234123412341234123412340000").unwrap(), 34; "default")]
#[test_case(vec![127], 34; "short")]
#[test_case(vec![0], 32; "literal")]
#[test_case(Vec::from_hex("a09bdb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df0000000000000000000000000000000000000000000000000000000000").unwrap(), 60; "long")]
#[test_case(Vec::from_hex("b83adb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df0000000000000000000000000000000000000000000000000000000000").unwrap(), 60; "long long")]
pub fn test_mock_rlp_string(mut input_bytes: Vec<u8>, max_len: usize) {
    let k = DEGREE;
    input_bytes.resize(max_rlp_encoding_len(max_len), 0u8);
    let circuit =
        rlp_string_circuit::<Fr>(CircuitBuilderStage::Mock, input_bytes, max_len, None, None);
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test_case(Vec::from_hex("a012341234123412341234123412341234123412341234123412341234123412340000").unwrap(), 34; "default")]
#[test_case(vec![127], 34; "short")]
#[test_case(vec![0], 32; "literal")]
#[test_case(Vec::from_hex("a09bdb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df0000000000000000000000000000000000000000000000000000000000").unwrap(), 60; "long")]
#[test_case(Vec::from_hex("b83adb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df0000000000000000000000000000000000000000000000000000000000").unwrap(), 60; "long long")]
pub fn prank_test_mock_rlp_string(mut input_bytes: Vec<u8>, max_len: usize) {
    let k = DEGREE;
    input_bytes.resize(max_rlp_encoding_len(max_len), 0u8);
    let prank_lens = [input_bytes.len(), 3, input_bytes.len(), 1];
    for (j, prank_len) in prank_lens.into_iter().enumerate() {
        for i in 0..prank_len {
            let circuit = rlp_string_circuit::<Fr>(
                CircuitBuilderStage::Mock,
                input_bytes.clone(),
                max_len,
                Some(i),
                Some(j),
            );
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_err(), "Unconstrained at {i}, should not have verified",);
        }
    }
}

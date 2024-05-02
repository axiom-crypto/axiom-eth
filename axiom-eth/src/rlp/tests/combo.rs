use std::fs::File;

use super::*;

use serde::{Deserialize, Serialize};
use test_case::test_case;

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
struct RlpComboTestInput {
    pub input: String,
    pub max_field_lens: Vec<usize>,
    pub is_var_len: bool,
    pub parsed: Vec<String>,
}

impl RlcCircuitInstructions<Fr> for RlpComboTestInput {
    type FirstPhasePayload = (RlpArrayWitness<Fr>, bool);

    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<Fr>,
        range: &RangeChip<Fr>,
    ) -> Self::FirstPhasePayload {
        let ctx = builder.base.main(0);
        let mut input_bytes: Vec<u8> = Vec::from_hex(&self.input).unwrap();
        let input_size = self.max_field_lens.iter().sum::<usize>() * 2;
        input_bytes.resize(input_size, 0u8);
        let inputs = ctx.assign_witnesses(input_bytes.iter().map(|x| Fr::from(*x as u64)));
        let chip = RlpChip::new(range, None);
        let witness =
            chip.decompose_rlp_array_phase0(ctx, inputs, &self.max_field_lens, self.is_var_len);
        assert_eq!(witness.field_witness.len(), self.parsed.len());
        for (item_witness, parsed) in witness.field_witness.iter().zip(self.parsed.iter()) {
            let parsed_bytes = Vec::from_hex(parsed).unwrap();

            let field = &item_witness.encoded_item;
            let parsed_bytes = parsed_bytes.iter().map(|x| Fr::from(*x as u64));
            for (a, b) in field.iter().zip(parsed_bytes) {
                assert_eq!(a.value(), &b);
            }
        }
        (witness, self.is_var_len)
    }

    fn virtual_assign_phase1(
        builder: &mut RlcCircuitBuilder<Fr>,
        range: &RangeChip<Fr>,
        rlc: &RlcChip<Fr>,
        (witness, is_var_len): Self::FirstPhasePayload,
    ) {
        let chip = RlpChip::new(range, Some(rlc));
        chip.decompose_rlp_array_phase1(builder.rlc_ctx_pair(), witness, is_var_len);
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![vec![]]
    }
}

#[test_case("src/rlp/test_data/list_of_strings.json" ; "fields")]
#[test_case("src/rlp/test_data/arrays_and_fields.json" ; "arrays and fields")]
#[test_case("src/rlp/test_data/nested_arrays.json" ; "nested arrays")]
#[test_case("src/rlp/test_data/array_of_literals_big.json" ; "big array of literals")]
#[test_case("src/rlp/test_data/nested_arrays_big.json" ; "big nested arrays")]

pub fn test_mock_rlp_combo(path: &str) {
    let k = DEGREE;
    let input: RlpComboTestInput =
        serde_json::from_reader(File::open(path).expect("path does not exist")).unwrap();

    let builder = RlcCircuitBuilder::from_stage(CircuitBuilderStage::Mock, 7)
        .use_k(DEGREE as usize)
        .use_lookup_bits(8);
    let circuit = RlcExecutor::new(builder, input);
    circuit.0.calculate_params(Some(20));

    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
}

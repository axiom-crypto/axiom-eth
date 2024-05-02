use std::fs::File;

use super::{
    chip::RlcChip,
    circuit::{builder::RlcCircuitBuilder, instructions::RlcCircuitInstructions, RlcCircuitParams},
    utils::executor::{RlcCircuit, RlcExecutor},
};
use ethers_core::k256::elliptic_curve::Field;
use halo2_base::{
    gates::{
        circuit::{BaseCircuitParams, CircuitBuilderStage},
        RangeChip, RangeInstructions,
    },
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr},
        plonk::{keygen_pk, keygen_vk, Error},
        poly::kzg::commitment::ParamsKZG,
    },
    utils::{
        testing::{check_proof, gen_proof},
        ScalarField,
    },
    AssignedValue,
};
use itertools::Itertools;
use rand::{rngs::StdRng, SeedableRng};
use test_log::test;

const K: usize = 16;
fn test_params() -> RlcCircuitParams {
    RlcCircuitParams {
        base: BaseCircuitParams {
            k: K,
            num_advice_per_phase: vec![1, 1],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![],
            lookup_bits: None,
            num_instance_columns: 0,
        },
        num_rlc_columns: 1,
    }
}

pub fn get_rlc_params(path: &str) -> RlcCircuitParams {
    serde_json::from_reader(File::open(path).unwrap()).unwrap()
}

struct Test<F: ScalarField> {
    padded_input: Vec<F>,
    len: usize,
}

struct TestPayload<F: ScalarField> {
    true_input: Vec<F>,
    inputs: Vec<AssignedValue<F>>,
    len: AssignedValue<F>,
}

impl<F: ScalarField> RlcCircuitInstructions<F> for Test<F> {
    type FirstPhasePayload = TestPayload<F>;
    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        _: &RangeChip<F>,
    ) -> Self::FirstPhasePayload {
        let ctx = builder.base.main(0);
        let true_input = self.padded_input[..self.len].to_vec();
        let inputs = ctx.assign_witnesses(self.padded_input.clone());
        let len = ctx.load_witness(F::from(self.len as u64));
        TestPayload { true_input, inputs, len }
    }

    fn virtual_assign_phase1(
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
        rlc: &RlcChip<F>,
        payload: Self::FirstPhasePayload,
    ) {
        let TestPayload { true_input, inputs, len } = payload;
        let (ctx_gate, ctx_rlc) = builder.rlc_ctx_pair();
        let gate = range.gate();
        let rlc_trace = rlc.compute_rlc((ctx_gate, ctx_rlc), gate, inputs, len);
        let rlc_val = *rlc_trace.rlc_val.value();
        let real_rlc = compute_rlc_acc(&true_input, *rlc.gamma());
        assert_eq!(real_rlc, rlc_val);
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![vec![]]
    }
}

fn compute_rlc_acc<F: ScalarField>(msg: &[F], r: F) -> F {
    let mut rlc = msg[0];
    for val in msg.iter().skip(1) {
        rlc = rlc * r + val;
    }
    rlc
}

fn rlc_test_circuit(
    stage: CircuitBuilderStage,
    inputs: Vec<Fr>,
    len: usize,
) -> RlcCircuit<Fr, Test<Fr>> {
    let params = test_params();
    let mut builder = RlcCircuitBuilder::from_stage(stage, 0).use_params(params);
    builder.base.set_lookup_bits(8); // not used, just to create range chip
    RlcExecutor::new(builder, Test { padded_input: inputs, len })
}

#[test]
pub fn test_mock_rlc() {
    let input_bytes = vec![
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
    .into_iter()
    .map(|x| Fr::from(x as u64))
    .collect_vec();
    let len = 32;

    let circuit = rlc_test_circuit(CircuitBuilderStage::Mock, input_bytes, len);
    MockProver::run(K as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
pub fn test_rlc() -> Result<(), Error> {
    let input_bytes = vec![
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
    .into_iter()
    .map(|x| Fr::from(x as u64))
    .collect_vec();
    let len = 32;

    let mut rng = StdRng::from_seed([0u8; 32]);
    let k = K as u32;
    let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
    let circuit =
        rlc_test_circuit(CircuitBuilderStage::Keygen, vec![Fr::ZERO; input_bytes.len()], 1);

    println!("vk gen started");
    let vk = keygen_vk(&params, &circuit)?;
    println!("vk gen done");
    let pk = keygen_pk(&params, vk, &circuit)?;
    println!("pk gen done");
    let break_points = circuit.0.builder.borrow().break_points();
    drop(circuit);
    println!();
    println!("==============STARTING PROOF GEN===================");

    let circuit = rlc_test_circuit(CircuitBuilderStage::Prover, input_bytes, len);
    circuit.0.builder.borrow_mut().set_break_points(break_points);
    let proof = gen_proof(&params, &pk, circuit);
    println!("proof gen done");
    check_proof(&params, pk.get_vk(), &proof, true);
    println!("verify done");
    Ok(())
}

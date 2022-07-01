use crate::{
    keccak::types::{ComponentTypeKeccak, KeccakVirtualInput, KeccakVirtualOutput},
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::component::{
        promise_loader::{comp_loader::ComponentCommiter, flatten_witness_to_rlc},
        types::{FixLenLogical, Flatten},
        utils::{into_key, load_logical_value},
        ComponentCircuit, ComponentType, LogicalResult, PromiseCallWitness,
    },
};

use halo2_base::{
    gates::GateInstructions, halo2_proofs::halo2curves::bn256::Fr, safe_types::SafeTypeChip,
    AssignedValue, Context,
};
use itertools::Itertools;
use snark_verifier_sdk::CircuitExt;
use zkevm_hashes::keccak::{
    component::circuit::shard::{KeccakComponentShardCircuit, KeccakComponentShardCircuitParams},
    vanilla::param::NUM_BYTES_TO_ABSORB,
};

use super::{
    promise::{KeccakComponentCommiter, KeccakFixLenCall, KeccakVarLenCall},
    types::KeccakLogicalInput,
};

fn verify_rlc_consistency(
    logical_input: KeccakLogicalInput,
    f: impl Fn(&mut Context<Fr>) -> Box<dyn PromiseCallWitness<Fr>>,
) {
    let output = logical_input.compute_output();

    let mut builder = RlcCircuitBuilder::<Fr>::new(false, 32);
    builder.set_k(18);
    builder.set_lookup_bits(8);
    // Mock gamma for testing.
    builder.gamma = Some(Fr::from([1, 5, 7, 8]));
    let range_chip = &builder.range_chip();
    let rlc_chip = builder.rlc_chip(&range_chip.gate);
    let (gate_ctx, rlc_ctx) = builder.rlc_ctx_pair();

    let assigned_output: KeccakVirtualOutput<AssignedValue<Fr>> =
        load_logical_value(gate_ctx, &output);
    let call = f(gate_ctx);

    let key = into_key(logical_input.clone());
    assert_eq!(&call.to_typeless_logical_input(), &key);

    let lr =
        LogicalResult::<Fr, ComponentTypeKeccak<Fr>>::new(logical_input.clone(), output.clone());
    let vrs_from_results = ComponentTypeKeccak::<Fr>::logical_result_to_virtual_rows(&lr);
    let assigned_vrs_from_results: Vec<(KeccakVirtualInput<_>, KeccakVirtualOutput<_>)> =
        vrs_from_results
            .into_iter()
            .map(|(input, output)| {
                (load_logical_value(gate_ctx, &input), load_logical_value(gate_ctx, &output))
            })
            .collect_vec();
    let rlc_from_results = ComponentTypeKeccak::<Fr>::rlc_virtual_rows(
        (gate_ctx, rlc_ctx),
        range_chip,
        &rlc_chip,
        &assigned_vrs_from_results,
    );

    let mut rlc_from_call = call.to_rlc((gate_ctx, rlc_ctx), range_chip, &rlc_chip);
    let output_rlc = flatten_witness_to_rlc(rlc_ctx, &rlc_chip, &assigned_output.into());
    let output_multiplier = rlc_chip.rlc_pow_fixed(
        gate_ctx,
        &range_chip.gate,
        KeccakVirtualOutput::<Fr>::get_num_fields(),
    );
    rlc_from_call = range_chip.gate.mul_add(gate_ctx, rlc_from_call, output_multiplier, output_rlc);

    assert_eq!(rlc_from_results.last().unwrap().value(), rlc_from_call.value());
}

#[test]
fn test_rlc_consistency() {
    let raw_bytes: [u8; 135] = [1; NUM_BYTES_TO_ABSORB - 1];
    let logical_input: KeccakLogicalInput = KeccakLogicalInput::new(raw_bytes.to_vec());
    // Fix-len
    verify_rlc_consistency(logical_input.clone(), |gate_ctx| {
        let assigned_raw_bytes =
            gate_ctx.assign_witnesses(raw_bytes.into_iter().map(|b| Fr::from(b as u64)));
        let fix_len_call = KeccakFixLenCall::new(SafeTypeChip::unsafe_to_fix_len_bytes_vec(
            assigned_raw_bytes,
            raw_bytes.len(),
        ));
        Box::new(fix_len_call)
    });
    // Var-len
    verify_rlc_consistency(logical_input, |gate_ctx| {
        let max_len = NUM_BYTES_TO_ABSORB;
        let len = gate_ctx.load_witness(Fr::from(raw_bytes.len() as u64));
        let var_len_bytes = vec![1; max_len];

        let assigned_var_len_bytes =
            gate_ctx.assign_witnesses(var_len_bytes.into_iter().map(|b| Fr::from(b as u64)));
        let var_len_call = KeccakVarLenCall::new(
            SafeTypeChip::unsafe_to_var_len_bytes_vec(assigned_var_len_bytes, len, max_len),
            10,
        );
        Box::new(var_len_call)
    });
}

// Test compute outputs against `instances()` implementation
#[test]
fn test_compute_outputs_commit_keccak() {
    let k: usize = 15;
    let num_unusable_row: usize = 109;
    let capacity: usize = 10;
    let publish_raw_outputs: bool = false;

    let inputs = vec![
        (0u8..200).collect::<Vec<_>>(),
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    // used capacity = 9
    let mut padded_inputs = inputs.clone();
    padded_inputs.push(vec![]);

    let params =
        KeccakComponentShardCircuitParams::new(k, num_unusable_row, capacity, publish_raw_outputs);
    let circuit = KeccakComponentShardCircuit::<Fr>::new(vec![], params, false);
    circuit.feed_input(Box::new(inputs)).unwrap();
    let commit = circuit.instances()[0][0];

    let res = circuit.compute_outputs().unwrap();
    assert_eq!(res.leaves()[0].commit, commit);
    assert_eq!(
        res.shards()[0].1.iter().map(|(i, _o)| i.clone()).collect_vec(),
        padded_inputs
            .into_iter()
            .map(|bytes| into_key(KeccakLogicalInput::new(bytes)))
            .collect_vec()
    );
}

/// Test `compute_native_commitment` against the custom `compute_outputs` implementation
#[test]
fn test_compute_native_commit_keccak() {
    let k: usize = 15;
    let num_unusable_row: usize = 109;
    let capacity: usize = 10;
    let publish_raw_outputs: bool = false;

    let inputs = vec![
        (0u8..200).collect::<Vec<_>>(),
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    // used capacity = 9
    let mut padded_inputs = inputs.clone();
    padded_inputs.push(vec![]);

    let params =
        KeccakComponentShardCircuitParams::new(k, num_unusable_row, capacity, publish_raw_outputs);
    let circuit = KeccakComponentShardCircuit::<Fr>::new(vec![], params, false);
    circuit.feed_input(Box::new(inputs)).unwrap();

    let res = circuit.compute_outputs().unwrap();
    let commit = res.leaves()[0].commit;

    let vt = padded_inputs
        .into_iter()
        .flat_map(|bytes| {
            let logical_input = KeccakLogicalInput::new(bytes);
            let output = logical_input.compute_output();
            let lr = LogicalResult::<Fr, ComponentTypeKeccak<Fr>>::new(logical_input, output);
            ComponentTypeKeccak::<Fr>::logical_result_to_virtual_rows(&lr)
        })
        .map(|(v_i, v_o)| (Flatten::from(v_i), Flatten::from(v_o)))
        .collect_vec();
    let commit2 = KeccakComponentCommiter::compute_native_commitment(&vt);
    assert_eq!(commit, commit2);
}

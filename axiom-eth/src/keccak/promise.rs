use std::{any::Any, marker::PhantomData};

use getset::Getters;
use halo2_base::{
    gates::{circuit::builder::BaseCircuitBuilder, GateInstructions, RangeChip, RangeInstructions},
    safe_types::{FixLenBytesVec, VarLenBytesVec},
    utils::bit_length,
    AssignedValue, Context,
    QuantumCell::Constant,
};
use itertools::Itertools;
use num_bigint::BigUint;
use snark_verifier::util::hash::Poseidon;
use snark_verifier_sdk::NativeLoader;
use zkevm_hashes::keccak::{
    component::{
        encode::{format_input, num_word_per_witness, pack_native_input},
        param::{POSEIDON_RATE, POSEIDON_T},
    },
    vanilla::{
        keccak_packed_multi::get_num_keccak_f,
        param::{NUM_BITS_PER_WORD, NUM_BYTES_TO_ABSORB},
    },
};

use crate::{
    rlc::chip::RlcChip,
    utils::component::{
        promise_loader::comp_loader::ComponentCommiter,
        types::Flatten,
        utils::{create_hasher, into_key, native_poseidon_hasher, try_from_key},
        ComponentCircuit, ComponentType, ComponentTypeId, LogicalInputValue, PromiseCallWitness,
        TypelessLogicalInput,
    },
    Field,
};

use super::types::{
    ComponentTypeKeccak, KeccakLogicalInput, KeccakVirtualInput, KeccakVirtualOutput,
    OutputKeccakShard, NUM_WITNESS_PER_KECCAK_F,
};

/// Keccak promise call for fixed-length inputs.
#[derive(Clone, Debug, Getters)]
pub struct KeccakFixLenCall<F: Field> {
    #[getset(get = "pub")]
    bytes: FixLenBytesVec<F>,
}
impl<F: Field> KeccakFixLenCall<F> {
    pub fn new(bytes: FixLenBytesVec<F>) -> Self {
        Self { bytes }
    }
    pub fn to_logical_input(&self) -> KeccakLogicalInput {
        let bytes_vec = self
            .bytes
            .bytes()
            .iter()
            .map(|b| b.as_ref().value().get_lower_64() as u8)
            .collect_vec();
        KeccakLogicalInput::new(bytes_vec)
    }
}

impl<F: Field> PromiseCallWitness<F> for KeccakFixLenCall<F> {
    fn get_component_type_id(&self) -> ComponentTypeId {
        ComponentTypeKeccak::<F>::get_type_id()
    }
    fn get_capacity(&self) -> usize {
        get_num_keccak_f(self.bytes.len())
    }
    fn to_rlc(
        &self,
        (gate_ctx, rlc_ctx): (&mut Context<F>, &mut Context<F>),
        range_chip: &RangeChip<F>,
        rlc_chip: &RlcChip<F>,
    ) -> AssignedValue<F> {
        let len = self.bytes.len();
        // NOTE: we pack with len + 1 instead of len for domain separation so the RLC can distinguish an empty input with is_final = 1 vs 0
        let len_p1 = gate_ctx.load_constant(F::from((len + 1) as u64));
        let packed_input =
            format_input(gate_ctx, &range_chip.gate, self.bytes.bytes(), len_p1).concat().concat();
        let rlc_fixed_trace = rlc_chip.compute_rlc_fixed_len(rlc_ctx, packed_input);
        rlc_fixed_trace.rlc_val
    }
    fn to_typeless_logical_input(&self) -> TypelessLogicalInput {
        into_key(self.to_logical_input())
    }
    fn get_mock_output(&self) -> Flatten<F> {
        let bytes_vec = self
            .bytes
            .bytes()
            .iter()
            .map(|b| b.as_ref().value().get_lower_64() as u8)
            .collect_vec();
        let logical_input = KeccakLogicalInput::new(bytes_vec);
        let output_val = logical_input.compute_output();
        output_val.into()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Keccak promise call for fixed-length inputs.
#[derive(Clone, Debug, Getters)]
pub struct KeccakVarLenCall<F: Field> {
    #[getset(get = "pub")]
    bytes: VarLenBytesVec<F>,
    min_len: usize,
}
impl<F: Field> KeccakVarLenCall<F> {
    pub fn new(bytes: VarLenBytesVec<F>, min_len: usize) -> Self {
        Self { bytes, min_len }
    }
    pub fn to_logical_input(&self) -> KeccakLogicalInput {
        let len = self.bytes.len().value().get_lower_64() as usize;
        let bytes_vec = self.bytes.bytes()[..len]
            .iter()
            .map(|b| b.as_ref().value().get_lower_64() as u8)
            .collect_vec();
        KeccakLogicalInput::new(bytes_vec)
    }
    /// Returns `num_keccak_f - 1`, where
    /// `num_keccak_f = bytes.len() / NUM_BYTES_TO_ABSORB + 1` is the true
    /// number of `keccak_f` permutations necessary for variable input length `bytes.len()`.
    pub fn num_keccak_f_m1(
        &self,
        gate_ctx: &mut Context<F>,
        range_chip: &RangeChip<F>,
    ) -> AssignedValue<F> {
        let max_len = self.bytes.max_len();
        let num_bits = bit_length(max_len as u64);
        let len = *self.bytes.len();
        let (num_keccak_f_m1, _) =
            range_chip.div_mod(gate_ctx, len, BigUint::from(NUM_BYTES_TO_ABSORB), num_bits);
        num_keccak_f_m1
    }
}

impl<F: Field> PromiseCallWitness<F> for KeccakVarLenCall<F> {
    fn get_component_type_id(&self) -> ComponentTypeId {
        ComponentTypeKeccak::<F>::get_type_id()
    }
    fn get_capacity(&self) -> usize {
        get_num_keccak_f(self.bytes.len().value().get_lower_64() as usize)
    }
    fn to_rlc(
        &self,
        (gate_ctx, rlc_ctx): (&mut Context<F>, &mut Context<F>),
        range_chip: &RangeChip<F>,
        rlc_chip: &RlcChip<F>,
    ) -> AssignedValue<F> {
        let bytes = self.bytes.ensure_0_padding(gate_ctx, &range_chip.gate);
        let num_keccak_f_m1 = self.num_keccak_f_m1(gate_ctx, range_chip);

        let len = bytes.len();
        let len_p1 = range_chip.gate.inc(gate_ctx, *len);

        let num_keccak_f = range_chip.gate.inc(gate_ctx, num_keccak_f_m1);
        let packed_input = format_input(gate_ctx, &range_chip.gate, bytes.bytes(), len_p1);
        let packed_input = packed_input.into_iter().flatten().flatten();

        let rlc_len = range_chip.gate.mul(
            gate_ctx,
            Constant(F::from(NUM_WITNESS_PER_KECCAK_F as u64)),
            num_keccak_f,
        );
        let rlc_trace = rlc_chip.compute_rlc_with_min_len(
            (gate_ctx, rlc_ctx),
            &range_chip.gate,
            packed_input,
            rlc_len,
            get_num_keccak_f(self.min_len) * NUM_WITNESS_PER_KECCAK_F,
        );
        rlc_trace.rlc_val
    }
    fn to_typeless_logical_input(&self) -> TypelessLogicalInput {
        into_key(self.to_logical_input())
    }
    fn get_mock_output(&self) -> Flatten<F> {
        let len = self.bytes.len().value().get_lower_64() as usize;
        let bytes_vec = self.bytes.bytes()[..len]
            .iter()
            .map(|b| b.as_ref().value().get_lower_64() as u8)
            .collect_vec();
        let logical_input: KeccakLogicalInput = KeccakLogicalInput::new(bytes_vec);
        let output_val: <ComponentTypeKeccak<F> as ComponentType<F>>::OutputValue =
            logical_input.compute_output();
        output_val.into()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn get_dummy_key<F: Field>(native_poseidon: &mut Poseidon<F, F, POSEIDON_T, POSEIDON_RATE>) -> F {
    native_poseidon.clear();
    // copied from encode_native_input, but save re-creating Spec above
    let witnesses_per_keccak_f = pack_native_input(&[]);
    for witnesses in witnesses_per_keccak_f {
        for absorbing in witnesses.chunks(POSEIDON_RATE) {
            // To avoid absorbing witnesses crossing keccak_fs together, pad 0s to make sure absorb.len() == RATE.
            let mut padded_absorb = [F::ZERO; POSEIDON_RATE];
            padded_absorb[..absorbing.len()].copy_from_slice(absorbing);
            native_poseidon.update(&padded_absorb);
        }
    }
    native_poseidon.squeeze()
}

/// KeccakComponentCommiter implements the commitment computation in KeccakComponentShardCircuit which uses a legacy way to compute commitment.
pub struct KeccakComponentCommiter<F: Field>(PhantomData<F>);

impl<F: Field> ComponentCommiter<F> for KeccakComponentCommiter<F> {
    /// This must match the commitment computation in [zkevm_hashes::keccak::component::circuit::shard::encode_inputs_from_keccak_fs] and
    /// [zkevm_hashes::keccak::component::circuit::shard::KeccakComponentShardCircuit::publish_outputs] with `publish_raw_outputs = false`.
    fn compute_commitment(
        builder: &mut BaseCircuitBuilder<F>,
        witness_virtual_rows: &[(Flatten<AssignedValue<F>>, Flatten<AssignedValue<F>>)],
    ) -> AssignedValue<F> {
        let range_chip = &builder.range_chip();
        let ctx = builder.main(0);

        let mut hasher = create_hasher::<F>();
        hasher.initialize_consts(ctx, &range_chip.gate);
        let dummy_key = {
            let mut native_poseidon = Poseidon::from_spec(&NativeLoader, hasher.spec().clone());
            get_dummy_key(&mut native_poseidon)
        };
        let dummy_input = ctx.load_constant(dummy_key);
        let parsed_virtual_rows: Vec<(KeccakVirtualInput<_>, KeccakVirtualOutput<_>)> =
            witness_virtual_rows
                .iter()
                .map(|(v_i, v_o)| {
                    (v_i.clone().try_into().unwrap(), v_o.clone().try_into().unwrap())
                })
                .collect_vec();
        // Constraint is_final of each virtual row
        let mut remaining_keccak_f = ctx.load_zero();
        for (v_i, _) in &parsed_virtual_rows {
            let (_, length_placeholder) = range_chip.div_mod(
                ctx,
                v_i.packed_input[0],
                BigUint::from(1u128 << NUM_BITS_PER_WORD),
                NUM_BITS_PER_WORD * num_word_per_witness::<F>(),
            );
            // num_keccak_f = length / NUM_BYTES_TO_ABSORB + 1
            // num_keccak_f_dec = num_keccak_f - 1
            let (num_keccak_f_dec, _) = range_chip.div_mod(
                ctx,
                length_placeholder,
                BigUint::from(NUM_BYTES_TO_ABSORB),
                NUM_BITS_PER_WORD,
            );
            let remaining_keccak_f_is_zero = range_chip.gate.is_zero(ctx, remaining_keccak_f);
            let remaining_keccak_f_dec = range_chip.gate.dec(ctx, remaining_keccak_f);
            remaining_keccak_f = range_chip.gate.select(
                ctx,
                num_keccak_f_dec,
                remaining_keccak_f_dec,
                remaining_keccak_f_is_zero,
            );
            let is_final = range_chip.gate.is_zero(ctx, remaining_keccak_f);
            ctx.constrain_equal(&is_final, &v_i.is_final);
        }

        let mut inputs_to_poseidon = Vec::with_capacity(parsed_virtual_rows.len());
        let mut virtual_outputs = Vec::with_capacity(parsed_virtual_rows.len());
        for (v_i, v_o) in parsed_virtual_rows {
            inputs_to_poseidon.push(v_i.into());
            virtual_outputs.push(v_o);
        }
        let poseidon_results =
            hasher.hash_compact_chunk_inputs(ctx, &range_chip.gate, &inputs_to_poseidon);
        let keccak_outputs = poseidon_results
            .into_iter()
            .zip_eq(virtual_outputs)
            .map(|(po, vo)| {
                let key = range_chip.gate.select(ctx, po.hash(), dummy_input, po.is_final());
                vec![key, vo.hash.lo(), vo.hash.hi()]
            })
            .concat();
        hasher.hash_fix_len_array(ctx, &range_chip.gate, &keccak_outputs)
    }

    /// This code path is currently never used, but it should still be consistent with
    /// `self.compute_commitment`.
    ///
    /// We do not do input validation of `is_final` in this function and just assume it is correct.
    fn compute_native_commitment(witness_virtual_rows: &[(Flatten<F>, Flatten<F>)]) -> F {
        let mut hasher = native_poseidon_hasher();
        let dummy_key = get_dummy_key(&mut hasher);
        hasher.clear();
        let keccak_outputs: Vec<_> = witness_virtual_rows
            .iter()
            .flat_map(|(v_i, v_o)| {
                let (v_i, v_o): (KeccakVirtualInput<_>, KeccakVirtualOutput<_>) =
                    (v_i.clone().try_into().unwrap(), v_o.clone().try_into().unwrap());
                hasher.update(&v_i.packed_input);
                let key = if v_i.is_final == F::ONE {
                    let key = hasher.squeeze();
                    hasher.clear();
                    key
                } else {
                    dummy_key
                };
                let [hi, lo] = v_o.hash.hi_lo();
                [key, lo, hi]
            })
            .collect();
        hasher.clear();
        hasher.update(&keccak_outputs);
        hasher.squeeze()
    }
}

/// A helper function to fulfill keccak promises for a Component for testing.
pub fn generate_keccak_shards_from_calls<F: Field>(
    comp_circuit: &dyn ComponentCircuit<F>,
    capacity: usize,
) -> anyhow::Result<OutputKeccakShard> {
    let calls = comp_circuit.compute_promise_calls()?;
    let keccak_type_id = ComponentTypeKeccak::<F>::get_type_id();
    let keccak_calls = calls.get(&keccak_type_id).ok_or(anyhow::anyhow!("no keccak calls"))?;
    let mut used_capacity = 0;
    let responses = keccak_calls
        .iter()
        .map(|call| {
            let li = try_from_key::<KeccakLogicalInput>(&call.logical_input).unwrap();
            used_capacity += <KeccakLogicalInput as LogicalInputValue<F>>::get_capacity(&li);
            (li.bytes.clone().into(), None)
        })
        .collect_vec();
    log::info!("Keccak used capacity: {}", used_capacity);
    if used_capacity > capacity {
        return Err(anyhow::anyhow!(
            "used capacity {} exceeds capacity {}",
            used_capacity,
            capacity
        ));
    }
    Ok(OutputKeccakShard { responses, capacity })
}

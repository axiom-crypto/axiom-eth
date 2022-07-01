use super::{param::*, types::*};
use super::{ComponentType, FlattenVirtualRow};
use crate::Field;
use halo2_base::gates::GateInstructions;
use halo2_base::gates::RangeChip;
use halo2_base::poseidon::hasher::spec::OptimizedPoseidonSpec;
use halo2_base::AssignedValue;
use halo2_base::Context;
use itertools::Itertools;
use serde::de::DeserializeOwned;
use serde::Serialize;
use snark_verifier::{loader::native::NativeLoader, util::hash::Poseidon};

/// Do not recreate this unless you need to: it recomputes the OptimizedPoseidonSpec each time.
///
/// Unfortunately we can't use lazy_static due to the generic type `F`.
pub fn native_poseidon_hasher<F: Field>() -> Poseidon<F, F, POSEIDON_T, POSEIDON_RATE> {
    Poseidon::<F, F, POSEIDON_T, POSEIDON_RATE>::new::<
        POSEIDON_R_F,
        POSEIDON_R_P,
        POSEIDON_SECURE_MDS,
    >(&NativeLoader)
}

/// Do not recreate this unless you need to: it is computationally expensive.
///
/// Unfortunately we can't use lazy_static due to the generic type `F`.
pub fn optimized_poseidon_spec<F: Field>() -> OptimizedPoseidonSpec<F, POSEIDON_T, POSEIDON_RATE> {
    OptimizedPoseidonSpec::<F, POSEIDON_T, POSEIDON_RATE>::new::<
        POSEIDON_R_F,
        POSEIDON_R_P,
        POSEIDON_SECURE_MDS,
    >()
}

pub fn compute_poseidon<F: Field>(payload: &[F]) -> F {
    let mut native_poseidon_sponge = native_poseidon_hasher();
    native_poseidon_sponge.update(payload);
    native_poseidon_sponge.squeeze()
}

/// Return values of merkle tree nodes. Top to bottom, left to right.
pub fn compute_poseidon_merkle_tree<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    initialized_hasher: &PoseidonHasher<F>,
    leaves: Vec<AssignedValue<F>>,
) -> Vec<AssignedValue<F>> {
    let len = leaves.len();
    // Also implict len > 0
    assert!(len.is_power_of_two());
    if len == 1 {
        return leaves;
    }
    let next_level =
        leaves.chunks(2).map(|c| initialized_hasher.hash_fix_len_array(ctx, gate, c)).collect_vec();
    let mut ret: Vec<AssignedValue<F>> =
        compute_poseidon_merkle_tree(ctx, gate, initialized_hasher, next_level);
    ret.extend(leaves);
    ret
}

pub fn compress_flatten_pair<F: Field>(
    ctx: &mut Context<F>,
    range_chip: &RangeChip<F>,
    input: &Flatten<AssignedValue<F>>,
    output: &Flatten<AssignedValue<F>>,
) -> Vec<AssignedValue<F>> {
    let mut result = vec![];
    let mut used_bits = 0;
    let const_zero = ctx.load_zero();
    let mut witness_current = const_zero;
    for (a, bits) in input
        .fields
        .iter()
        .chain(output.fields.iter())
        .zip_eq(input.field_size.iter().chain(output.field_size))
    {
        let bits = *bits;
        // If bits > capacity, this is a hacky way to speicify this field taking a whole witness.
        if used_bits + bits <= (F::CAPACITY as usize) {
            let const_mul = ctx.load_constant(range_chip.gate.pow_of_two[used_bits]);
            witness_current = range_chip.gate.mul_add(ctx, const_mul, *a, witness_current);
            if used_bits + bits == (F::CAPACITY as usize) {
                result.push(witness_current);
                used_bits = 0;
                witness_current = const_zero;
            } else {
                used_bits += bits;
            }
        } else {
            // TODO: maybe decompose a here to fully utilize capacity.
            result.push(witness_current);
            used_bits = bits;
            witness_current = *a;
        }
    }
    if used_bits > 0 {
        result.push(witness_current);
    }
    result
}

/// Load logical value as witness using Flatten as intermediate. V and W should come from
/// the same struct.
pub fn load_logical_value<F: Field, V: FixLenLogical<F>, W: FixLenLogical<AssignedValue<F>>>(
    ctx: &mut Context<F>,
    v: &V,
) -> W {
    let flatten_value: Flatten<F> = v.clone().into();
    let flatten_witness = flatten_value.assign(ctx);
    W::try_from(flatten_witness).unwrap()
}

/// Get logical value from witness using Flatten as intermediate. V and W should come from
/// the same struct.
pub fn get_logical_value<F: Field, W: FixLenLogical<AssignedValue<F>>, V: FixLenLogical<F>>(
    w: &W,
) -> V {
    let flatten_witness: Flatten<AssignedValue<F>> = w.clone().into();
    let flatten_value: Flatten<F> = flatten_witness.into();
    V::try_from(flatten_value).unwrap()
}

pub fn create_hasher<F: Field>() -> PoseidonHasher<F> {
    // Construct in-circuit Poseidon hasher.
    let spec = OptimizedPoseidonSpec::new::<POSEIDON_R_F, POSEIDON_R_P, POSEIDON_SECURE_MDS>();
    PoseidonHasher::new(spec)
}

pub fn compute_commitment<F: Field, T: ComponentType<F>>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    initialized_hasher: &PoseidonHasher<F>,
    io_pairs: Vec<(T::InputWitness, T::OutputWitness)>,
) -> AssignedValue<F> {
    let flatten_io_pairs = io_pairs.into_iter().map(|(i, o)| (i.into(), o.into())).collect_vec();
    let commit = compute_commitment_with_flatten(ctx, gate, initialized_hasher, &flatten_io_pairs);
    log::debug!("component_type_id: {} commit: {:?}", T::get_type_id(), commit.value());
    commit
}

#[allow(clippy::type_complexity)]
pub fn compute_commitment_with_flatten<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    initialized_hasher: &PoseidonHasher<F>,
    io_pairs: &[FlattenVirtualRow<AssignedValue<F>>],
) -> AssignedValue<F> {
    if io_pairs.is_empty() {
        return ctx.load_zero();
    }
    let to_commit: Vec<AssignedValue<F>> = io_pairs
        .iter()
        .flat_map(|(i, o)| [i.fields.clone(), o.fields.clone()].concat())
        .collect_vec();
    initialized_hasher.hash_fix_len_array(ctx, gate, &to_commit)
}

/// Convert LogicalInputValue into key which can be used to look up promise results.
pub fn into_key(key: impl Serialize) -> Vec<u8> {
    bincode::serialize(&key).unwrap()
}

/// Convert key back into LogicalInputValue.
pub fn try_from_key<T: DeserializeOwned>(key: &[u8]) -> anyhow::Result<T> {
    bincode::deserialize(key).map_err(anyhow::Error::from)
}

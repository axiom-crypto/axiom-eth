use crate::Field;
use crate::{
    mpt::MPTProof,
    utils::{bytes_be_to_u128, bytes_be_to_uint},
};
use halo2_base::{
    gates::GateInstructions,
    safe_types::{SafeBool, SafeByte, SafeBytes32, SafeTypeChip},
    utils::ScalarField,
    AssignedValue, Context,
};

use crate::utils::hilo::HiLo;

/// Takes `bytes` as fixed length byte array, left pads with 0s, and then converts
/// to HiLo form. Optimization where if `bytes` is less than 16 bytes, it can
/// skip the Hi part.
pub fn pack_bytes_to_hilo<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: &[SafeByte<F>],
) -> HiLo<AssignedValue<F>> {
    let len = bytes.len();
    assert!(len <= 32);
    let hi = if len > 16 {
        let hi_bytes = &bytes[0..len - 16];
        bytes_be_to_uint(ctx, gate, hi_bytes, hi_bytes.len())
    } else {
        ctx.load_zero()
    };
    let lo = {
        let lo_len = if len > 16 { 16 } else { len };
        let lo_bytes = &bytes[len - lo_len..len];
        bytes_be_to_uint(ctx, gate, lo_bytes, lo_len)
    };
    HiLo::from_hi_lo([hi, lo])
}

pub fn select_hi_lo<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    if_true: &HiLo<AssignedValue<F>>,
    if_false: &HiLo<AssignedValue<F>>,
    condition: SafeBool<F>,
) -> HiLo<AssignedValue<F>> {
    let condition = *condition.as_ref();
    let hi = gate.select(ctx, if_true.hi(), if_false.hi(), condition);
    let lo = gate.select(ctx, if_true.lo(), if_false.lo(), condition);
    HiLo::from_hi_lo([hi, lo])
}

pub fn select_hi_lo_by_indicator<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    values: &[HiLo<AssignedValue<F>>],
    indicator: Vec<AssignedValue<F>>,
) -> HiLo<AssignedValue<F>> {
    let his = values.iter().map(|hilo| hilo.hi());
    let los = values.iter().map(|hilo| hilo.lo());
    let hi = gate.select_by_indicator(ctx, his, indicator.clone());
    let lo = gate.select_by_indicator(ctx, los, indicator);
    HiLo::from_hi_lo([hi, lo])
}

// Is there a more Rust way to do this?
/// Conversion from `&[SafeByte]` to `Vec<AssignedValue<F>>`
pub fn safe_bytes_vec_into<F: ScalarField>(bytes: &[SafeByte<F>]) -> Vec<AssignedValue<F>> {
    bytes.iter().map(|b| *b.as_ref()).collect()
}

/// Conversion from [SafeBytes32] to [HiLo]
pub fn safe_bytes32_to_hi_lo<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: &SafeBytes32<F>,
) -> HiLo<AssignedValue<F>> {
    let bytes = SafeTypeChip::unsafe_to_fix_len_bytes_vec(bytes.value().to_vec(), 32);
    HiLo::from_hi_lo(bytes_be_to_u128(ctx, gate, bytes.bytes()).try_into().unwrap())
}

/// Conversion from the MPT root as bytes32 to [HiLo]. Unsafe because this assumes that
/// the root bytes are constrained to be bytes somewhere else.
pub fn unsafe_mpt_root_to_hi_lo<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    proof: &MPTProof<F>,
) -> HiLo<AssignedValue<F>> {
    let bytes = SafeTypeChip::unsafe_to_fix_len_bytes_vec(proof.root_hash_bytes.clone(), 32);
    HiLo::from_hi_lo(bytes_be_to_u128(ctx, gate, bytes.bytes()).try_into().unwrap())
}

pub fn encode_const_u8_to_safe_bytes<F: ScalarField>(
    ctx: &mut Context<F>,
    constant: u8,
) -> [SafeByte<F>; 1] {
    let encoded = constant.to_be_bytes().map(|b| F::from(b as u64));
    let raw = ctx.load_constants(&encoded).try_into().unwrap();
    SafeTypeChip::unsafe_to_fix_len_bytes::<1>(raw).into_bytes()
}

pub fn encode_const_u16_to_safe_bytes<F: ScalarField>(
    ctx: &mut Context<F>,
    constant: u16,
) -> [SafeByte<F>; 2] {
    let encoded = constant.to_be_bytes().map(|b| F::from(b as u64));
    let raw = ctx.load_constants(&encoded).try_into().unwrap();
    SafeTypeChip::unsafe_to_fix_len_bytes::<2>(raw).into_bytes()
}

pub fn encode_const_u32_to_safe_bytes<F: ScalarField>(
    ctx: &mut Context<F>,
    constant: u32,
) -> [SafeByte<F>; 4] {
    let encoded = constant.to_be_bytes().map(|b| F::from(b as u64));
    let raw = ctx.load_constants(&encoded).try_into().unwrap();
    SafeTypeChip::unsafe_to_fix_len_bytes::<4>(raw).into_bytes()
}

pub fn encode_const_u64_to_safe_bytes<F: ScalarField>(
    ctx: &mut Context<F>,
    constant: u64,
) -> [SafeByte<F>; 8] {
    let encoded = constant.to_be_bytes().map(|b| F::from(b as u64));
    let raw = ctx.load_constants(&encoded).try_into().unwrap();
    SafeTypeChip::unsafe_to_fix_len_bytes::<8>(raw).into_bytes()
}

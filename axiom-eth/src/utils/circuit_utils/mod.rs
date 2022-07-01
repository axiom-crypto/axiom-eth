use std::{cmp::max, ops::Range};

use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    safe_types::{SafeBool, SafeTypeChip},
    utils::{bit_length, ScalarField},
    AssignedValue, Context,
    QuantumCell::Constant,
};

use itertools::Itertools;

pub mod bytes;

// save typing..
/// See [GateInstructions::is_equal]
pub fn is_equal_usize<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    a: AssignedValue<F>,
    b: usize,
) -> SafeBool<F> {
    SafeTypeChip::unsafe_to_bool(gate.is_equal(ctx, a, Constant(F::from(b as u64))))
}

/// See [RangeInstructions::is_less_than]
pub fn is_lt_usize<F: ScalarField>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    a: AssignedValue<F>,
    b: usize,
    max_bits: usize,
) -> SafeBool<F> {
    let bit = range.is_less_than(ctx, a, Constant(F::from(b as u64)), max_bits);
    SafeTypeChip::unsafe_to_bool(bit)
}

/// See [RangeInstructions::is_less_than]
/// `a >= b` iff `b - 1 < a`
pub fn is_gte_usize<F: ScalarField>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    a: AssignedValue<F>,
    b: usize,
    max_bits: usize,
) -> SafeBool<F> {
    let bit = if b == 0 {
        ctx.load_constant(F::ONE)
    } else {
        range.is_less_than(ctx, Constant(F::from(b as u64 - 1)), a, max_bits)
    };
    SafeTypeChip::unsafe_to_bool(bit)
}

/// Returns whether `a` is in the range `[range.start, range.end)`.
/// Assumes `a` and `range.end` are both less than `2^max_bits`.
pub fn is_in_range<F: ScalarField>(
    ctx: &mut Context<F>,
    range_chip: &impl RangeInstructions<F>,
    a: AssignedValue<F>,
    range: Range<usize>,
    max_bits: usize,
) -> SafeBool<F> {
    let is_gte = is_gte_usize(ctx, range_chip, a, range.start, max_bits);
    let is_lt = is_lt_usize(ctx, range_chip, a, range.end, max_bits);
    let is_in_range = range_chip.gate().and(ctx, *is_gte.as_ref(), *is_lt.as_ref());
    SafeTypeChip::unsafe_to_bool(is_in_range)
}

/// Returns `min(a, b)`.
/// Assumes `a` and `b` are both less than `2^max_bits`.
pub fn min_with_usize<F: ScalarField>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    a: AssignedValue<F>,
    b: usize,
    max_bits: usize,
) -> AssignedValue<F> {
    let const_b = Constant(F::from(b as u64));
    let lt = range.is_less_than(ctx, a, const_b, max_bits);
    range.gate().select(ctx, a, const_b, lt)
}

/// Creates the length `len` array `mask` with `mask[i] = i < threshold ? 1 : 0`.
///
/// Denoted `unsafe` because it assumes that `threshold <= len`.
pub fn unsafe_lt_mask<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    threshold: AssignedValue<F>,
    len: usize,
) -> Vec<SafeBool<F>> {
    let t = threshold.value().get_lower_64() as usize;
    let mut last = None;
    let mask = (0..len)
        .map(|i| {
            let mut bit = ctx.load_witness(F::from(i < t));
            gate.assert_bit(ctx, bit);
            // constrain the list goes 1, ..., 1, 0, 0, ..., 0
            if let Some(last) = last {
                bit = gate.and(ctx, bit, last);
            }
            last = Some(bit);
            bit
        })
        .collect_vec();
    let sum = gate.sum(ctx, mask.clone());
    ctx.constrain_equal(&sum, &threshold);
    mask.into_iter().map(|x| SafeTypeChip::unsafe_to_bool(x)).collect()
}

/// Constrains that `array[i] = 0` for `i > len`.
///
/// ## Assumptions
/// - Marked unsafe because we assume `len <= array.len()`
pub fn unsafe_constrain_trailing_zeros<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    array: &mut [AssignedValue<F>],
    len: AssignedValue<F>,
) {
    let mask = unsafe_lt_mask(ctx, gate, len, array.len());
    for (byte, mask) in array.iter_mut().zip(mask) {
        *byte = gate.mul(ctx, *byte, mask);
    }
}

pub fn log2_ceil<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    x: AssignedValue<F>,
    max_bits: usize,
) -> AssignedValue<F> {
    let mut bits = gate.num_to_bits(ctx, x, max_bits);
    let total_bits = gate.sum(ctx, bits.clone());
    for i in (0..max_bits - 1).rev() {
        bits[i] = gate.or(ctx, bits[i], bits[i + 1]);
    }
    let bit_length = gate.sum(ctx, bits);
    let is_pow2 = gate.is_equal(ctx, total_bits, Constant(F::ONE));
    gate.sub(ctx, bit_length, is_pow2)
}

/// Returns `array[chunk_size * idx.. chunk_size * (idx+1)]`.
///
/// Assumes that `chunk_size * idx < array.len()`. Otherwise will return all zeros.
pub fn extract_array_chunk<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    array: &[AssignedValue<F>],
    idx: AssignedValue<F>,
    chunk_size: usize,
) -> Vec<AssignedValue<F>> {
    let num_chunks = (array.len() + chunk_size - 1) / chunk_size;
    let indicator = gate.idx_to_indicator(ctx, idx, num_chunks);
    let const_zero = ctx.load_zero();
    (0..chunk_size)
        .map(|i| {
            let entries =
                (0..num_chunks).map(|j| *array.get(chunk_size * j + i).unwrap_or(&const_zero));
            gate.select_by_indicator(ctx, entries, indicator.clone())
        })
        .collect()
}

/// Returns `array[chunk_size * idx.. chunk_size * (idx+1)]` and constrains that any entries beyond `len` must be zero.
///
/// Also returns `chunk_size * idx < len` as [SafeBool].
///
/// ## Assumptions
/// - `array.len()` is fixed at compile time
/// - `len <= array.len()`
/// - `idx` has been range checked to have at most `idx_max_bits` bits
pub fn extract_array_chunk_and_constrain_trailing_zeros<F: ScalarField>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    array: &[AssignedValue<F>],
    len: AssignedValue<F>,
    idx: AssignedValue<F>,
    chunk_size: usize,
    idx_max_bits: usize,
) -> (Vec<AssignedValue<F>>, SafeBool<F>) {
    let gate = range.gate();
    let mut chunk = extract_array_chunk(ctx, gate, array, idx, chunk_size);
    let chunk_size = chunk_size as u64;
    let start = gate.mul(ctx, idx, Constant(F::from(chunk_size)));
    let max_len_bits = bit_length(array.len() as u64);
    // not worth optimizing:
    let max_bits = max(max_len_bits, idx_max_bits + bit_length(chunk_size));
    let is_lt = range.is_less_than(ctx, start, len, max_bits);
    // chunk_len = min(len - idx * chunk_size, chunk_size)
    let mut chunk_len = gate.sub(ctx, len, start);
    chunk_len = gate.mul(ctx, chunk_len, is_lt);
    chunk_len = min_with_usize(ctx, range, chunk_len, chunk_size as usize, max_len_bits);
    unsafe_constrain_trailing_zeros(ctx, gate, &mut chunk, chunk_len);

    (chunk, SafeTypeChip::unsafe_to_bool(is_lt))
}

/// Given fixed length array `array` checks that either `array[0]` is nonzero or `var_len == 0`. Does nothing if `array` is empty.
///
/// There technically does not need to be any relation between `array` and `var_len` in this implementation. However the usual use case is where `array` is a fixed length array that is meant to represent a variable length array of length `var_len`.
pub fn constrain_no_leading_zeros<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    array: &[AssignedValue<F>],
    var_len: AssignedValue<F>,
) {
    if array.is_empty() {
        return;
    }
    let leading_zero = gate.is_zero(ctx, array[0]);
    let mut no_leading_zero = gate.not(ctx, leading_zero);
    let len_is_zero = gate.is_zero(ctx, var_len);
    no_leading_zero = gate.or(ctx, no_leading_zero, len_is_zero);
    gate.assert_is_const(ctx, &no_leading_zero, &F::ONE);
}

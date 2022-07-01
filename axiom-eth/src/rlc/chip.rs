use halo2_base::{
    gates::GateInstructions,
    utils::{bit_length, ScalarField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use itertools::Itertools;
use std::{
    iter,
    sync::{RwLock, RwLockReadGuard},
};

use super::{
    circuit::builder::RlcContextPair,
    types::{RlcFixedTrace, RlcTrace, RlcVar, RlcVarPtr},
};

/// This chip provides functions related to computing Random Linear Combinations (RLCs) using powers of a random
/// challenge value `gamma`. Throughout we assume that `gamma` is supplied through the Halo2 Challenge API.
/// The chip can be borrowed so that the cache can be updated to higher powers.
#[derive(Debug)]
pub struct RlcChip<F: ScalarField> {
    /// `gamma_pow_cached[i] = gamma^{2^i}`
    gamma_pow_cached: RwLock<Vec<AssignedValue<F>>>, // Use RwLock so we can read from multiple threads if necessary
    gamma: F,
}

impl<F: ScalarField> RlcChip<F> {
    pub fn new(gamma: F) -> Self {
        Self { gamma_pow_cached: RwLock::new(vec![]), gamma }
    }

    pub fn gamma(&self) -> &F {
        &self.gamma
    }

    /// `gamma_pow_cached[i] = gamma^{2^i}`
    pub fn gamma_pow_cached(&self) -> RwLockReadGuard<Vec<AssignedValue<F>>> {
        self.gamma_pow_cached.read().unwrap()
    }

    /// Computes the RLC of `inputs` where the given `inputs` is assumed to be padded to a fixed length `max_len`,
    /// but the RLC is computed for a variable length `len`. If `a := inputs, l := len, r := gamma` then
    /// ```
    /// RLC(a, l) = \sum_{i = 0}^{l - 1} a_i r^{l - 1 - i}
    /// ```
    /// We assume all cells of `inputs` are in a previous phase, and `ctx_gate` and `ctx_rlc` are both
    /// [`Context`]s in a later phase. Here `ctx_gate` is used for [halo2_base] gate assignments, while `ctx_rlc`
    /// is used for assignments in special RLC gate assignments.
    ///
    /// Assumes `0 <= len <= max_len`.
    pub fn compute_rlc(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        gate: &impl GateInstructions<F>,
        inputs: impl IntoIterator<Item = AssignedValue<F>>,
        len: AssignedValue<F>,
    ) -> RlcTrace<F> {
        self.compute_rlc_with_min_len((ctx_gate, ctx_rlc), gate, inputs, len, 0)
    }

    /// Same as `compute_rlc` but assumes `min_len <= len <= max_len` as an optimization.
    /// The case `len = 0` is handled with some special treatment
    pub fn compute_rlc_with_min_len(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        gate: &impl GateInstructions<F>,
        inputs: impl IntoIterator<Item = AssignedValue<F>>,
        len: AssignedValue<F>,
        min_len: usize,
    ) -> RlcTrace<F> {
        let mut inputs = inputs.into_iter();
        let is_zero = gate.is_zero(ctx_gate, len);
        let shift_amt = if min_len != 0 { min_len } else { 1 };
        let shifted_len = gate.sub(ctx_gate, len, Constant(F::from(shift_amt as u64)));
        let idx = gate.select(ctx_gate, Constant(F::ZERO), shifted_len, is_zero);

        let mut max_len: usize = 0;
        let row_offset = ctx_rlc.advice.len() as isize;
        if let Some(first) = inputs.next() {
            max_len = 1;
            let mut running_rlc = *first.value();
            let rlc_vals = iter::once(Existing(first)).chain(inputs.flat_map(|input| {
                max_len += 1;
                running_rlc = running_rlc * self.gamma() + input.value();
                [Existing(input), Witness(running_rlc)]
            }));
            if ctx_rlc.witness_gen_only() {
                ctx_rlc.assign_region(rlc_vals, []);
            } else {
                let rlc_vals = rlc_vals.collect_vec();
                ctx_rlc.assign_region(rlc_vals, (0..2 * max_len as isize - 2).step_by(2));
            }
        }
        // ctx_rlc.advice looks like | rlc0=val0 | val1 | rlc1 | val2 | rlc2 | ... | rlc_{max_len - 1} |
        // therefore we want to index into `2 * (len - 1)` unless len is 0, in which case we just return 0
        assert!(min_len <= max_len);
        let rlc_val = if max_len == 0 {
            ctx_gate.load_zero()
        } else if shift_amt == max_len {
            // same as ctx_rlc.get(-1):
            ctx_rlc.get(row_offset + 2 * (max_len - 1) as isize)
        } else {
            gate.select_from_idx(
                ctx_gate,
                (shift_amt - 1..max_len).map(|i| ctx_rlc.get(row_offset + 2 * i as isize)),
                idx,
            )
        };
        // rlc_val = rlc_val * (1 - is_zero)
        let rlc_val = gate.mul_not(ctx_gate, is_zero, rlc_val);

        RlcTrace { rlc_val, len, max_len }
    }

    /// Same as [`compute_rlc`] but now the input is of known fixed length.
    pub fn compute_rlc_fixed_len(
        &self,
        ctx_rlc: &mut Context<F>,
        inputs: impl IntoIterator<Item = AssignedValue<F>>,
    ) -> RlcFixedTrace<F> {
        let mut inputs = inputs.into_iter();
        if let Some(first) = inputs.next() {
            let mut running_rlc = *first.value();
            let mut len: usize = 1;
            let rlc_vals = iter::once(Existing(first)).chain(inputs.flat_map(|input| {
                len += 1;
                running_rlc = running_rlc * self.gamma() + input.value();
                [Existing(input), Witness(running_rlc)]
            }));
            let rlc_val = if ctx_rlc.witness_gen_only() {
                ctx_rlc.assign_region_last(rlc_vals, [])
            } else {
                let rlc_vals = rlc_vals.collect_vec();
                ctx_rlc.assign_region_last(rlc_vals, (0..2 * (len as isize) - 2).step_by(2))
            };
            RlcFixedTrace { rlc_val, len }
        } else {
            RlcFixedTrace { rlc_val: ctx_rlc.load_zero(), len: 0 }
        }
    }

    /// Define the dynamic RLC: RLC(a, l) = \sum_{i = 0}^{l - 1} a_i r^{l - 1 - i}
    /// * We have that:
    ///     RLC(a || b, l_a + l_b) = RLC(a, l_a) * r^{l_a} + RLC(b, l_b).
    /// * Prop: For sequences b^0, \ldots, b^{k-1} with l(b^i) = l_i and
    ///     RLC(a, l) = RLC(b^0, l_0) * r^{l_1 + ... + l_{k - 1}}
    ///                 + RLC(b^1, l_1) * r^{l_2 + ... + l_{k - 1}}
    ///                 ... + RLC(b^{k - 1}, l_{k - 1}), and
    ///     l = l_0 + ... + l_{k - 1},
    ///   then a = b^0 || ... || b^{k - 1}.
    /// * Pf: View both sides as polynomials in r.
    ///
    /// If `var_num_frags` is Some, then it concatenates the first `var_num_frags` inputs into the RLC. Otherwise it concatenates all inputs.
    ///
    /// # Assumptions
    /// * each tuple of the input is (RLC(a, l), l) for some sequence a_i of length l
    /// * all rlc_len values have been range checked
    /// * `ctx_gate` should be in later phase than `inputs`
    /// * `0 < var_num_frags <= inputs.len()`
    ///
    // if num_frags.value() = 0, then (rlc = 0, len = 0) because of how `select_from_idx` works (`num_frags_minus_1` will be very large)
    pub fn rlc_concat(
        &self,
        ctx_gate: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        inputs: impl IntoIterator<Item = RlcTrace<F>>,
        var_num_frags: Option<AssignedValue<F>>,
    ) -> RlcTrace<F> {
        let mut inputs = inputs.into_iter();
        let (size, hi) = inputs.size_hint();
        // size only used for capacity estimation
        debug_assert_eq!(Some(size), hi);

        let mut partial_rlc = Vec::with_capacity(size);
        let mut partial_len = Vec::with_capacity(size);

        let initial = inputs.next().unwrap();
        let mut running_rlc = initial.rlc_val;
        let mut running_len = initial.len;
        let mut running_max_len = initial.max_len;
        partial_rlc.push(running_rlc);
        partial_len.push(running_len);
        for input in inputs {
            let RlcTrace { rlc_val, len, max_len } = input;
            running_len = gate.add(ctx_gate, running_len, len);
            let gamma_pow = self.rlc_pow(ctx_gate, gate, len, bit_length(max_len as u64));
            running_rlc = gate.mul_add(ctx_gate, running_rlc, gamma_pow, rlc_val);
            partial_len.push(running_len);
            partial_rlc.push(running_rlc);
            running_max_len += max_len;
        }
        if let Some(num_frags) = var_num_frags {
            let num_frags_minus_1 = gate.sub(ctx_gate, num_frags, Constant(F::ONE));
            let indicator = gate.idx_to_indicator(ctx_gate, num_frags_minus_1, partial_len.len());
            let total_len = gate.select_by_indicator(ctx_gate, partial_len, indicator.clone());
            let rlc_select = gate.select_by_indicator(ctx_gate, partial_rlc, indicator);
            RlcTrace { rlc_val: rlc_select, len: total_len, max_len: running_max_len }
        } else {
            RlcTrace {
                rlc_val: partial_rlc.pop().unwrap(),
                len: partial_len.pop().unwrap(),
                max_len: running_max_len,
            }
        }
    }

    /// We compute `rlc_concat` of `inputs` (the first `var_num_frags` if Some), and then constrain the result equals `concatenation`.
    ///
    /// `ctx_gate` and `ctx_rlc` should be in later phase than `inputs`
    pub fn constrain_rlc_concat<'a>(
        &self,
        ctx_gate: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        inputs: impl IntoIterator<Item = RlcTrace<F>>,
        concatenation: impl Into<RlcVarPtr<'a, F>>,
        var_num_frags: Option<AssignedValue<F>>,
    ) {
        let claimed_concat = self.rlc_concat(ctx_gate, gate, inputs, var_num_frags);
        rlc_constrain_equal(ctx_gate, &claimed_concat, concatenation.into());
    }

    fn load_gamma(&self, ctx_rlc: &mut Context<F>, gamma: F) -> AssignedValue<F> {
        ctx_rlc.assign_region_last([Constant(F::ONE), Constant(F::ZERO), Witness(gamma)], [0])
    }

    /// Updates `gamma_pow_cached` to contain assigned values for `gamma^{2^i}` for `i = 0,...,cache_bits - 1` where `gamma` is the challenge value
    ///
    /// WARNING: this must be called in a deterministic way. It is NOT thread-safe, even though the compiler thinks it is.
    pub fn load_rlc_cache(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        gate: &impl GateInstructions<F>,
        cache_bits: usize,
    ) {
        if cache_bits <= self.gamma_pow_cached().len() {
            return;
        }
        log::debug!(
            "Loading RLC cache ({} bits) with existing {} bits",
            cache_bits,
            self.gamma_pow_cached().len()
        );
        let mut gamma_pow_cached = self.gamma_pow_cached.write().unwrap();
        if gamma_pow_cached.is_empty() {
            let gamma_assigned = self.load_gamma(ctx_rlc, *self.gamma());
            gamma_pow_cached.push(gamma_assigned);
        };

        for _ in gamma_pow_cached.len()..cache_bits {
            let last = *gamma_pow_cached.last().unwrap();
            let sq = gate.mul(ctx_gate, last, last);
            gamma_pow_cached.push(sq);
        }
    }

    /// Computes `gamma^pow` where `gamma` is the challenge value.
    pub fn rlc_pow(
        &self,
        ctx_gate: &mut Context<F>, // ctx_gate in SecondPhase
        gate: &impl GateInstructions<F>,
        pow: AssignedValue<F>,
        mut pow_bits: usize,
    ) -> AssignedValue<F> {
        if pow_bits == 0 {
            pow_bits = 1;
        }
        assert!(pow_bits <= self.gamma_pow_cached().len());

        let bits = gate.num_to_bits(ctx_gate, pow, pow_bits);
        let mut out = None;

        for (bit, &gamma_pow) in bits.into_iter().zip(self.gamma_pow_cached().iter()) {
            let multiplier = gate.select(ctx_gate, gamma_pow, Constant(F::ONE), bit);
            out = Some(if let Some(prev) = out {
                gate.mul(ctx_gate, multiplier, prev)
            } else {
                multiplier
            });
        }
        out.unwrap()
    }

    /// Computes `gamma^pow` where `gamma` is the challenge value.
    pub fn rlc_pow_fixed(
        &self,
        ctx_gate: &mut Context<F>, // ctx_gate in SecondPhase
        gate: &impl GateInstructions<F>,
        pow: usize,
    ) -> AssignedValue<F> {
        if pow == 0 {
            return ctx_gate.load_constant(F::ONE);
        }
        let gamma_pow2 = self.gamma_pow_cached();
        let bits = bit_length(pow as u64);
        assert!(bits <= gamma_pow2.len());
        let mut out = None;
        for i in 0..bits {
            if pow >> i & 1 == 1 {
                let multiplier = gamma_pow2[i];
                out =
                    Some(out.map(|prev| gate.mul(ctx_gate, multiplier, prev)).unwrap_or(multiplier))
            }
        }
        out.unwrap()
    }
}

/// Define the dynamic RLC: `RLC(a, l) = \sum_{i = 0}^{l - 1} a_i r^{l - 1 - i}`
/// where `a` is a variable length vector of length `l`.
///
/// We have `a == b` iff `RLC(a, l_a) == RLC(b, l_b)` AND `l_a == l_b`.
/// The length equality constraint is necessary because `a` and `b` can have leading zeros.
pub fn rlc_is_equal<F: ScalarField>(
    ctx_gate: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    a: impl Into<RlcVar<F>>,
    b: impl Into<RlcVar<F>>,
) -> AssignedValue<F> {
    let a = a.into();
    let b = b.into();
    let len_is_equal = gate.is_equal(ctx_gate, a.len, b.len);
    let rlc_is_equal = gate.is_equal(ctx_gate, a.rlc_val, b.rlc_val);
    gate.and(ctx_gate, len_is_equal, rlc_is_equal)
}

pub fn rlc_constrain_equal<'a, F: ScalarField>(
    ctx: &mut Context<F>,
    a: impl Into<RlcVarPtr<'a, F>>,
    b: impl Into<RlcVarPtr<'a, F>>,
) {
    let a = a.into();
    let b = b.into();
    ctx.constrain_equal(a.len, b.len);
    ctx.constrain_equal(a.rlc_val, b.rlc_val);
}

pub fn rlc_select<F: ScalarField>(
    ctx_gate: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    a: impl Into<RlcVar<F>>,
    b: impl Into<RlcVar<F>>,
    condition: AssignedValue<F>,
) -> RlcVar<F> {
    let a = a.into();
    let b = b.into();
    let len = gate.select(ctx_gate, a.len, b.len, condition);
    let rlc_val = gate.select(ctx_gate, a.rlc_val, b.rlc_val, condition);
    RlcVar { rlc_val, len }
}

pub fn rlc_select_from_idx<F: ScalarField, R>(
    ctx_gate: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    a: impl IntoIterator<Item = R>,
    idx: AssignedValue<F>,
) -> RlcVar<F>
where
    R: Into<RlcVar<F>>,
{
    let a = a.into_iter();
    let (len, hi) = a.size_hint();
    assert_eq!(Some(len), hi);
    let indicator = gate.idx_to_indicator(ctx_gate, idx, len);
    rlc_select_by_indicator(ctx_gate, gate, a, indicator)
}

pub fn rlc_select_by_indicator<F: ScalarField, R>(
    ctx_gate: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    a: impl IntoIterator<Item = R>,
    indicator: Vec<AssignedValue<F>>,
) -> RlcVar<F>
where
    R: Into<RlcVar<F>>,
{
    let (a_len, a_rlc): (Vec<_>, Vec<_>) = a
        .into_iter()
        .map(|a| {
            let a = a.into();
            (a.len, a.rlc_val)
        })
        .unzip();
    let len = gate.select_by_indicator(ctx_gate, a_len, indicator.clone());
    let rlc_val = gate.select_by_indicator(ctx_gate, a_rlc, indicator);
    RlcVar { rlc_val, len }
}

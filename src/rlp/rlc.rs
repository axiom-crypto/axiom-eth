use crate::halo2_proofs::{
    plonk::{Advice, Challenge, Column, ConstraintSystem, FirstPhase, SecondPhase, Selector},
    poly::Rotation,
};
use halo2_base::{
    gates::GateInstructions,
    utils::{bit_length, ScalarField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use itertools::Itertools;
use std::{
    iter,
    marker::PhantomData,
    sync::{RwLock, RwLockReadGuard},
};

pub const FIRST_PHASE: usize = 0;
pub const RLC_PHASE: usize = 1;

#[derive(Clone, Copy, Debug)]
/// RLC of a vector of `F` values of variable length but known maximum length
pub struct RlcTrace<F: ScalarField> {
    pub rlc_val: AssignedValue<F>, // in SecondPhase
    pub len: AssignedValue<F>,     // in FirstPhase
    pub max_len: usize,
    // We no longer store the input values as they should be exposed elsewhere
    // pub values: Vec<AssignedValue<F>>,
}

#[derive(Clone, Copy, Debug)]
/// RLC of a trace of known fixed length
pub struct RlcFixedTrace<F: ScalarField> {
    pub rlc_val: AssignedValue<F>, // SecondPhase
    // pub values: Vec<AssignedValue<'v, F>>, // FirstPhase
    pub len: usize,
}

#[derive(Clone, Debug)]
/// This config consists of a variable number of advice columns, all in `SecondPhase`.
/// Each advice column has a selector column that enables a custom gate to aid RLC computation.
///
/// The intention is that this chip is only used for the actual RLC computation. All other operations should use `GateInstructions` by advancing the phase to `SecondPhase`.
///
/// Make sure that the `context_id` of `RlcChip` is different from that of any `FlexGateConfig` or `RangeConfig` you are using.
pub struct RlcConfig<F: ScalarField> {
    pub basic_gates: Vec<(Column<Advice>, Selector)>,
    pub gamma: Challenge,
    _marker: PhantomData<F>,
}

impl<F: ScalarField> RlcConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, num_advice: usize) -> Self {
        let basic_gates = (0..num_advice)
            .map(|_| {
                let a = meta.advice_column_in(SecondPhase);
                meta.enable_equality(a);
                let q = meta.selector();
                (a, q)
            })
            .collect_vec();

        let gamma = meta.challenge_usable_after(FirstPhase);

        for &(rlc, q) in basic_gates.iter() {
            meta.create_gate("RLC computation", |meta| {
                let q = meta.query_selector(q);
                let rlc_prev = meta.query_advice(rlc, Rotation::cur());
                let val = meta.query_advice(rlc, Rotation::next());
                let rlc_curr = meta.query_advice(rlc, Rotation(2));
                // TODO: see if reducing number of distinct rotation sets speeds up SHPLONK:
                // Phantom query so rotation set is also size 4 to match `FlexGateConfig`
                // meta.query_advice(rlc, Rotation(3));

                let gamma = meta.query_challenge(gamma);

                vec![q * (rlc_prev * gamma + val - rlc_curr)]
            });
        }

        Self { basic_gates, gamma, _marker: PhantomData }
    }
}

/// This chip provides functions related to computing Random Linear Combinations (RLCs) using powers of a random
/// challenge value `gamma`. Throughout we assume that `gamma` is supplied through the Halo2 Challenge API.
/// The chip can be borrowed so that the cache can be updated to higher powers.
#[derive(Debug)]
pub struct RlcChip<F: ScalarField> {
    /// `gamma_pow_cached[i] = gamma^{2^i}`
    gamma_pow_cached: RwLock<Vec<AssignedValue<F>>>, // Use RwLock so we can read from multiple threads if necessary
    gamma: F,
}

/// Wrapper so we don't need to pass around two contexts separately. The pair consists of `(ctx_gate, ctx_rlc)` where
/// * `ctx_gate` should be an `RLC_PHASE` context for use with `GateChip`.
/// * `ctx_rlc` should be a context for use with `RlcChip`.
pub(crate) type RlcContextPair<'a, F> = (&'a mut Context<F>, &'a mut Context<F>);

impl<F: ScalarField> RlcChip<F> {
    pub fn new(gamma: F) -> Self {
        Self { gamma_pow_cached: RwLock::new(vec![]), gamma }
    }

    pub fn gamma(&self) -> &F {
        &self.gamma
    }

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
        let mut inputs = inputs.into_iter();
        let is_zero = gate.is_zero(ctx_gate, len);
        let len_minus_one = gate.sub(ctx_gate, len, Constant(F::one()));
        let idx = gate.select(ctx_gate, Constant(F::zero()), len_minus_one, is_zero);

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

        let rlc_val = if max_len == 0 {
            ctx_gate.load_zero()
        } else {
            gate.select_from_idx(
                ctx_gate,
                // TODO: optimize this with iterator on ctx_rlc.advice
                (0..2 * max_len as isize).step_by(2).map(|i| ctx_rlc.get(row_offset + i)),
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
    //
    /// Assumes:
    /// * each tuple of the input is (RLC(a, l), l) for some sequence a_i of length l
    /// * all rlc_len values have been range checked
    ///
    /// `inputs[i] = (rlc_input, len, max_len)`
    ///
    /// `ctx_gate` should be in later phase than `inputs`
    pub fn constrain_rlc_concat(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        gate: &impl GateInstructions<F>,
        inputs: impl IntoIterator<Item = (AssignedValue<F>, AssignedValue<F>, usize)>,
        (concat_rlc, concat_len): (&AssignedValue<F>, &AssignedValue<F>),
    ) {
        let mut inputs = inputs.into_iter();

        let (mut running_rlc, mut running_len, _) = inputs.next().unwrap();
        for (input, len, max_len) in inputs {
            running_len = gate.add(ctx_gate, running_len, len);
            let gamma_pow =
                self.rlc_pow((ctx_gate, ctx_rlc), gate, len, bit_length(max_len as u64));
            running_rlc = gate.mul_add(ctx_gate, running_rlc, gamma_pow, input);
        }
        ctx_gate.constrain_equal(&running_rlc, concat_rlc);
        ctx_gate.constrain_equal(&running_len, concat_len);
    }

    /// Same as `constrain_rlc_concat` but now the actual length of `inputs` to use is variable:
    /// these are referred to as "fragments".
    ///
    /// Assumes 0 < num_frags <= max_num_frags.
    ///
    /// `ctx_gate` and `ctx_rlc` should be in later phase than `inputs`
    pub fn constrain_rlc_concat_var(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        gate: &impl GateInstructions<F>,
        inputs: impl IntoIterator<Item = (AssignedValue<F>, AssignedValue<F>, usize)>,
        (concat_rlc, concat_len): (&AssignedValue<F>, &AssignedValue<F>),
        num_frags: AssignedValue<F>,
        max_num_frags: usize,
    ) {
        debug_assert!(!num_frags.value().is_zero_vartime(), "num_frags must be positive.");

        let mut inputs = inputs.into_iter();
        let (size, hi) = inputs.size_hint();
        // size only used for capacity estimation
        debug_assert_eq!(Some(size), hi);

        let mut partial_rlc = Vec::with_capacity(size);
        let mut partial_len = Vec::with_capacity(size);

        let (mut running_rlc, mut running_len, _) = inputs.next().unwrap();
        partial_rlc.push(running_rlc);
        partial_len.push(running_len);
        for (input, len, max_len) in inputs {
            running_len = gate.add(ctx_gate, running_len, len);
            let gamma_pow =
                self.rlc_pow((ctx_gate, ctx_rlc), gate, len, bit_length(max_len as u64));
            running_rlc = gate.mul_add(ctx_gate, running_rlc, gamma_pow, input);
            partial_len.push(running_len);
            partial_rlc.push(running_rlc);
        }
        assert_eq!(partial_rlc.len(), max_num_frags);

        let num_frags_minus_1 = gate.sub(ctx_gate, num_frags, Constant(F::one()));
        let total_len = gate.select_from_idx(ctx_gate, partial_len, num_frags_minus_1);
        ctx_gate.constrain_equal(&total_len, concat_len);

        let rlc_select = gate.select_from_idx(ctx_gate, partial_rlc, num_frags_minus_1);
        ctx_gate.constrain_equal(&rlc_select, concat_rlc);
    }

    fn load_gamma(&self, ctx_rlc: &mut Context<F>, gamma: F) -> AssignedValue<F> {
        ctx_rlc.assign_region_last([Constant(F::one()), Constant(F::zero()), Witness(gamma)], [0])
    }

    /// Updates `gamma_pow_cached` to contain assigned values for `gamma^{2^i}` for `i = 0,...,cache_bits - 1` where `gamma` is the challenge value
    pub fn load_rlc_cache(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        gate: &impl GateInstructions<F>,
        cache_bits: usize,
    ) {
        if cache_bits <= self.gamma_pow_cached().len() {
            return;
        }
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
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        gate: &impl GateInstructions<F>,
        pow: AssignedValue<F>,
        mut pow_bits: usize,
    ) -> AssignedValue<F> {
        if pow_bits == 0 {
            pow_bits = 1;
        }
        self.load_rlc_cache((ctx_gate, ctx_rlc), gate, pow_bits);

        let bits = gate.num_to_bits(ctx_gate, pow, pow_bits);
        let mut out = None;

        for (bit, &gamma_pow) in bits.into_iter().zip(self.gamma_pow_cached().iter()) {
            let multiplier = gate.select(ctx_gate, gamma_pow, Constant(F::one()), bit);
            out = Some(if let Some(prev) = out {
                gate.mul(ctx_gate, multiplier, prev)
            } else {
                multiplier
            });
        }
        out.unwrap()
    }
}

// to deal with selecting / comparing RLC of variable length strings

#[derive(Clone, Copy, Debug)]
pub struct RlcVar<F: ScalarField> {
    pub rlc_val: AssignedValue<F>,
    pub len: AssignedValue<F>,
}

impl<F: ScalarField> From<RlcTrace<F>> for RlcVar<F> {
    fn from(trace: RlcTrace<F>) -> Self {
        RlcVar { rlc_val: trace.rlc_val, len: trace.len }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RlcVarPtr<'a, F: ScalarField> {
    pub rlc_val: &'a AssignedValue<F>,
    pub len: &'a AssignedValue<F>,
}

impl<'a, F: ScalarField> From<&'a RlcTrace<F>> for RlcVarPtr<'a, F> {
    fn from(trace: &'a RlcTrace<F>) -> Self {
        RlcVarPtr { rlc_val: &trace.rlc_val, len: &trace.len }
    }
}

impl<'a, F: ScalarField> From<&'a RlcVar<F>> for RlcVarPtr<'a, F> {
    fn from(trace: &'a RlcVar<F>) -> RlcVarPtr<'a, F> {
        RlcVarPtr { rlc_val: &trace.rlc_val, len: &trace.len }
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
    let (a_len, a_rlc): (Vec<_>, Vec<_>) = a
        .into_iter()
        .map(|a| {
            let a = a.into();
            (a.len, a.rlc_val)
        })
        .unzip();
    let len = gate.select_from_idx(ctx_gate, a_len, idx);
    let rlc_val = gate.select_from_idx(ctx_gate, a_rlc, idx);
    RlcVar { rlc_val, len }
}

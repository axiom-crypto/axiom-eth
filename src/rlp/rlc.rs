use crate::halo2_proofs::{
    circuit::Value,
    plonk::{Advice, Challenge, Column, ConstraintSystem, FirstPhase, SecondPhase, Selector},
    poly::Rotation,
};
use halo2_base::{
    gates::GateInstructions,
    utils::{bit_length, ScalarField},
    AssignedValue, Context, QuantumCell,
    QuantumCell::{Constant, Existing, Witness},
};
use itertools::Itertools;
use std::{iter, marker::PhantomData};

pub const RLC_PHASE: usize = 1;

#[derive(Clone, Debug)]
/// RLC of a trace of variable length but known maximum length
pub struct RlcTrace<'v, F: ScalarField> {
    pub rlc_val: AssignedValue<'v, F>, // in SecondPhase
    pub len: AssignedValue<'v, F>,     // everything else in FirstPhase
    // pub rlc_max: AssignedValue<'a, F>,
    /// After computing RLC we store the original values here
    pub values: Vec<AssignedValue<'v, F>>,
    pub max_len: usize,
}

#[derive(Clone, Debug)]
/// RLC of a trace of known fixed length
pub struct RlcFixedTrace<'v, F: ScalarField> {
    pub rlc_val: AssignedValue<'v, F>,     // SecondPhase
    pub values: Vec<AssignedValue<'v, F>>, // FirstPhase
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
    pub context_id: usize,
    pub gamma: Challenge,
    _marker: PhantomData<F>,
}

impl<F: ScalarField> RlcConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, num_advice: usize, context_id: usize) -> Self {
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

        Self { basic_gates, context_id, gamma, _marker: PhantomData }
    }
}

/// This chip is a wrapper around `RlcConfig` together with cached assigned values of the powers of the challenge `gamma`. The chip can be mutably borrowed so that the cache can be updated to higher powers.
#[derive(Clone, Debug)]
pub struct RlcChip<'g, F: ScalarField> {
    pub config: RlcConfig<F>,
    /// `gamma_pow_cached[i] = gamma^{2^i}`
    gamma_pow_cached: Vec<AssignedValue<'g, F>>,
    pub gamma: Value<F>,
}

impl<'g, F: ScalarField> RlcChip<'g, F> {
    pub fn new(config: RlcConfig<F>, gamma: Value<F>) -> RlcChip<'g, F> {
        Self { config, gamma_pow_cached: Vec::with_capacity(64), gamma }
    }

    pub fn get_challenge(&mut self, ctx: &mut Context<'_, F>) {
        #[cfg(feature = "halo2-axiom")]
        {
            // only allowed to update challenge if it is unknown
            // debug_assert!(value_to_option(self.gamma).is_none()); // doesn't work with mockprover
            self.gamma = ctx.region.get_challenge(self.config.gamma);
        }
    }

    pub fn basic_gates(&self) -> &[(Column<Advice>, Selector)] {
        &self.config.basic_gates
    }

    pub fn context_id(&self) -> usize {
        self.config.context_id
    }

    pub fn gamma_pow_cached(&self) -> &[AssignedValue<'g, F>] {
        &self.gamma_pow_cached
    }

    /// Similar to gate.assign_region but everything is in `SecondPhase` and `gate_offsets` are relative offsets for the "RLC computation" gate.
    ///
    /// Returns the inputs as a vector of `AssignedValue`s.
    pub fn assign_region<'a, 'v: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: impl IntoIterator<Item = QuantumCell<'a, 'v, F>>,
        gate_offsets: impl IntoIterator<Item = usize>,
    ) -> Vec<AssignedValue<'v, F>> {
        debug_assert_eq!(ctx.current_phase(), RLC_PHASE);
        let inputs = inputs.into_iter();
        let (len, hi) = inputs.size_hint();
        debug_assert_eq!(Some(len), hi);
        assert!(self.context_id() < ctx.advice_alloc.len());

        let (gate_index, row_offset) = {
            let alloc = ctx.advice_alloc.get_mut(self.context_id()).unwrap();

            if alloc.1 + len >= ctx.max_rows {
                alloc.1 = 0;
                alloc.0 += 1;
            }
            *alloc
        };

        let (rlc_column, q_rlc) =
            self.basic_gates().get(gate_index).expect("NOT ENOUGH RLC ADVICE COLUMNS");

        let rlc_assigned = inputs
            .enumerate()
            .map(|(i, input)| {
                ctx.assign_cell(
                    input,
                    *rlc_column,
                    #[cfg(feature = "display")]
                    self.context_id(),
                    row_offset + i,
                    #[cfg(feature = "halo2-pse")]
                    (RLC_PHASE as u8),
                )
            })
            .collect_vec();

        for idx in gate_offsets {
            q_rlc.enable(&mut ctx.region, row_offset + idx).unwrap();
        }

        ctx.advice_alloc[self.context_id()].1 += rlc_assigned.len();

        #[cfg(feature = "display")]
        {
            ctx.total_advice += rlc_assigned.len();
        }

        rlc_assigned
    }

    /// Same as `assign_region` except we only return the final assigned value. Optimized to avoid the memory allocation from collecting assignments into a vector.
    pub fn assign_region_last<'a, 'v: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: impl IntoIterator<Item = QuantumCell<'a, 'v, F>>,
        gate_offsets: impl IntoIterator<Item = usize>,
    ) -> AssignedValue<'v, F> {
        debug_assert_eq!(ctx.current_phase(), RLC_PHASE);
        let inputs = inputs.into_iter();
        let (len, hi) = inputs.size_hint();
        debug_assert_eq!(Some(len), hi);
        debug_assert!(self.context_id() < ctx.advice_alloc.len(), "context id out of bounds");

        let (gate_index, row_offset) = {
            let alloc = ctx.advice_alloc.get_mut(self.context_id()).unwrap();

            if alloc.1 + len >= ctx.max_rows {
                alloc.1 = 0;
                alloc.0 += 1;
            }
            *alloc
        };

        let (rlc_column, q_rlc) =
            self.basic_gates().get(gate_index).expect("NOT ENOUGH RLC ADVICE COLUMNS");

        let mut out = None;
        for (i, input) in inputs.enumerate() {
            out = Some(ctx.assign_cell(
                input,
                *rlc_column,
                #[cfg(feature = "display")]
                self.context_id(),
                row_offset + i,
                #[cfg(feature = "halo2-pse")]
                (RLC_PHASE as u8),
            ));
        }

        for idx in gate_offsets {
            q_rlc.enable(&mut ctx.region, row_offset + idx).unwrap();
        }

        ctx.advice_alloc[self.context_id()].1 += len;

        #[cfg(feature = "display")]
        {
            ctx.total_advice += len;
        }

        out.unwrap()
    }

    /// `inputs` should all be assigned cells in `FirstPhase`.
    ///
    /// Assumes `0 <= len <= max_len`.
    pub fn compute_rlc<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        gate: &impl GateInstructions<F>,
        inputs: Vec<AssignedValue<'v, F>>,
        len: AssignedValue<'v, F>,
    ) -> RlcTrace<'v, F> {
        let max_len = inputs.len();
        // This part can be done in either `FirstPhase` or `SecondPhase`
        let is_zero = gate.is_zero(ctx, &len);
        let len_minus_one = gate.sub(ctx, Existing(&len), Constant(F::one()));
        let idx =
            gate.select(ctx, Constant(F::zero()), Existing(&len_minus_one), Existing(&is_zero));

        // From now on we need to be in `SecondPhase` to use challenge `gamma`
        debug_assert_eq!(ctx.current_phase(), RLC_PHASE);

        let assigned = if inputs.is_empty() {
            vec![]
        } else {
            let mut running_rlc = inputs[0].value().copied();
            let rlc_vals =
                iter::once(Existing(&inputs[0])).chain(inputs.iter().skip(1).flat_map(|input| {
                    running_rlc = running_rlc * self.gamma + input.value();
                    [Existing(input), Witness(running_rlc)]
                }));
            self.assign_region(ctx, rlc_vals, (0..2 * max_len - 2).step_by(2))
        };

        let rlc_val = if inputs.is_empty() {
            gate.load_zero(ctx)
        } else {
            gate.select_from_idx(ctx, assigned.iter().step_by(2).map(Existing), Existing(&idx))
        };

        // rlc_val = rlc_val * (1 - is_zero)
        let rlc_val = gate.mul_not(ctx, Existing(&is_zero), Existing(&rlc_val));

        RlcTrace {
            rlc_val,
            len,
            values: inputs,
            max_len,
            /* rlc_max: if inputs.is_empty() { rlc_val.clone() } else { assigned.pop().unwrap() } */
        }
    }

    pub fn compute_rlc_fixed_len<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        gate: &impl GateInstructions<F>,
        inputs: Vec<AssignedValue<'v, F>>,
    ) -> RlcFixedTrace<'v, F> {
        let len = inputs.len();

        if len == 0 {
            return RlcFixedTrace { rlc_val: gate.load_zero(ctx), values: inputs, len };
        }

        let rlc_val = {
            let mut running_rlc = inputs[0].value().copied();
            let rlc_vals =
                iter::once(Existing(&inputs[0])).chain(inputs.iter().skip(1).flat_map(|input| {
                    running_rlc = running_rlc * self.gamma + input.value();
                    [Existing(input), Witness(running_rlc)]
                }));
            self.assign_region_last(ctx, rlc_vals, (0..2 * len - 2).step_by(2))
        };

        RlcFixedTrace { rlc_val, values: inputs, len }
    }

    /// Define the dynamic RLC: RLC(a, l) = \sum_{i = 0}^{l - 1} a_i r^{l - 1 - i}
    /// * We have that:
    ///     RLC(a || b, l_a + l_b) = RLC(a, l_a) * r^{l_a} + RLC(b, l_b).
    /// * Prop: For sequences b^0, \ldots, b^{k-1} with l(b^i) = l_i and
    ///     RLC(a, l) = RLC(b^0, l_0) * r^{l_1 + ... + l_{k - 1}}
    ///                 + RLC(b^1, l_1) * r^{l_2 + ... + l_{k - 1}}
    ///                 ... + RLC(b^k, l_k), and
    ///     l = l_0 + ... + l_{k - 1},
    ///   then a = b^1 || ... || b^k.
    /// * Pf: View both sides as polynomials in r.
    //
    /// Assumes:
    /// * each tuple of the input is (RLC(a, l), l) for some sequence a_i of length l
    /// * all rlc_len values have been range checked
    ///
    /// `inputs[i] = (rlc_input, len, max_len)`
    pub fn constrain_rlc_concat<'a, 'v: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        gate: &impl GateInstructions<F>,
        inputs: impl IntoIterator<Item = (&'a AssignedValue<'v, F>, &'a AssignedValue<'v, F>, usize)>,
        concat: (&AssignedValue<'v, F>, &AssignedValue<'v, F>),
    ) {
        debug_assert_eq!(ctx.current_phase(), RLC_PHASE);

        let mut inputs = inputs.into_iter();

        let (mut running_rlc, mut running_len, _) = inputs.next().unwrap();
        let mut tmp_rlc;
        let mut tmp_len;
        for (input, len, max_len) in inputs {
            tmp_len = gate.add(ctx, Existing(running_len), Existing(len));
            let gamma_pow = self.rlc_pow(ctx, gate, len, bit_length(max_len as u64));
            tmp_rlc =
                gate.mul_add(ctx, Existing(running_rlc), Existing(&gamma_pow), Existing(input));
            running_len = &tmp_len;
            running_rlc = &tmp_rlc;
        }
        ctx.region.constrain_equal(running_rlc.cell(), concat.0.cell());
        ctx.region.constrain_equal(running_len.cell(), concat.1.cell());
    }

    /// Same as `constrain_rlc_concat` but now the actual length of `rlc_inputs` to use is variable: these are referred to as "fragments".
    ///
    /// Assumes 0 < num_frags <= max_num_frags.
    pub fn constrain_rlc_concat_var<'a, 'v: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        gate: &impl GateInstructions<F>,
        inputs: impl IntoIterator<Item = (&'a AssignedValue<'v, F>, &'a AssignedValue<'v, F>, usize)>,
        concat: (&AssignedValue<'v, F>, &AssignedValue<'v, F>),
        num_frags: &AssignedValue<F>,
        max_num_frags: usize,
        rlc_cache: &[AssignedValue<F>],
    ) {
        debug_assert_eq!(ctx.current_phase(), RLC_PHASE);
        #[cfg(debug_assertions)]
        {
            num_frags.value().map(|v| {
                if v.is_zero_vartime() {
                    panic!("num_frags must be positive.")
                }
            });
        }

        let mut inputs = inputs.into_iter();
        let (size, hi) = inputs.size_hint();
        debug_assert_eq!(Some(size), hi);

        let mut partial_rlc = Vec::with_capacity(size);
        let mut partial_len = Vec::with_capacity(size);

        let first = inputs.next().unwrap();
        partial_rlc.push(first.0.clone());
        partial_len.push(first.1.clone());
        for (input, len, max_len) in inputs {
            debug_assert!(rlc_cache.len() >= bit_length(max_len as u64));
            let running_len = gate.add(ctx, Existing(partial_len.last().unwrap()), Existing(len));
            let gamma_pow = self.rlc_pow(ctx, gate, len, bit_length(max_len as u64));
            let running_rlc = gate.mul_add(
                ctx,
                Existing(partial_rlc.last().unwrap()),
                Existing(&gamma_pow),
                Existing(input),
            );
            partial_len.push(running_len);
            partial_rlc.push(running_rlc);
        }
        assert_eq!(partial_rlc.len(), max_num_frags);

        let num_frags_minus_1 = gate.sub(ctx, Existing(num_frags), Constant(F::one()));
        let total_len = gate.select_from_idx(
            ctx,
            partial_len.iter().map(Existing),
            Existing(&num_frags_minus_1),
        );
        // println!("TEST2 {:?} {:?}", total_len.value(), concat.1.value());
        ctx.region.constrain_equal(total_len.cell(), concat.1.cell());

        let concat_select = gate.select_from_idx(
            ctx,
            partial_rlc.iter().map(Existing),
            Existing(&num_frags_minus_1),
        );
        ctx.region.constrain_equal(concat_select.cell(), concat.0.cell());
    }

    /// Updates `gamma_pow_cached` to contain assigned values for `gamma^{2^i}` for `i = 0,...,cache_bits - 1` where `gamma` is the challenge value
    pub fn load_rlc_cache(
        &mut self,
        ctx: &mut Context<'_, F>,
        gate: &impl GateInstructions<F>,
        cache_bits: usize,
    ) {
        if cache_bits <= self.gamma_pow_cached.len() {
            return;
        }
        if self.gamma_pow_cached.is_empty() {
            let gamma = self.assign_region_last(
                ctx,
                vec![Constant(F::one()), Constant(F::zero()), Witness(self.gamma)],
                vec![0],
            );
            self.gamma_pow_cached.push(gamma);
        };

        assert_eq!(ctx.current_phase(), RLC_PHASE);
        for _ in self.gamma_pow_cached.len()..cache_bits {
            let last = self.gamma_pow_cached.last().unwrap();
            let sq = gate.mul(ctx, Existing(last), Existing(last));
            self.gamma_pow_cached.push(sq);
        }
    }

    /// Computes `gamma^pow` where `gamma` is the challenge value.
    pub fn rlc_pow<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        gate: &impl GateInstructions<F>,
        pow: &AssignedValue<'v, F>,
        mut pow_bits: usize,
    ) -> AssignedValue<'v, F>
    where
        'g: 'v,
    {
        if pow_bits == 0 {
            pow_bits = 1;
        }
        debug_assert!(pow_bits <= self.gamma_pow_cached.len());
        debug_assert_eq!(ctx.current_phase(), RLC_PHASE);

        let bits = gate.num_to_bits(ctx, pow, pow_bits);
        let mut out = None;

        for (bit, gamma_pow) in bits.iter().zip(self.gamma_pow_cached.iter()) {
            let multiplier =
                gate.select(ctx, Existing(gamma_pow), Constant(F::one()), Existing(bit));
            out = Some(if let Some(prev) = out {
                gate.mul(ctx, Existing(&multiplier), Existing(&prev))
            } else {
                multiplier
            });
        }
        out.unwrap()
    }
}

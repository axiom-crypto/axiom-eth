use halo2_base::{
    gates::{
        range::{RangeConfig, RangeStrategy, RangeStrategy::Vertical},
        GateInstructions, RangeInstructions,
    },
    AssignedValue, Context, ContextParams, QuantumCell,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{
        Advice, Challenge, Circuit, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed,
        Instance, SecondPhase, Selector,
    },
    poly::Rotation,
};
use std::{cmp::max, marker::PhantomData, rc::Rc};

use eth_types::Field;

pub fn compute_rlc<F: Field>(msg: &Vec<u8>, r: F) -> F {
    let mut coeff = r;
    let mut rlc = F::from(msg[0] as u64);
    for val in msg[1..].iter() {
        rlc = rlc + F::from(*val as u64) * coeff;
        coeff = coeff * r;
    }
    rlc
}

pub fn compute_rlc_acc<F: Field>(msg: &Vec<u8>, r: F) -> F {
    let mut rlc = F::from(msg[0] as u64);
    for val in msg[1..].iter() {
        rlc = rlc * r + F::from(*val as u64);
    }
    rlc
}

pub fn log2(x: usize) -> usize {
    let mut log = 0;
    let mut y = x;
    while y > 0 {
        y = y / 2;
        log = log + 1;
    }
    return log;
}

#[derive(Clone, Debug)]
pub struct RlcTrace<F: Field> {
    pub rlc_val: AssignedValue<F>,
    pub rlc_len: AssignedValue<F>,
    pub max_len: usize,
}

#[derive(Clone, Debug)]
pub struct BasicRlcChip<F: Field> {
    pub val: Column<Advice>,
    pub rlc: Column<Advice>,
    pub q_rlc: Selector,
    pub q_mul: Selector,
    _marker: PhantomData<F>,
}

impl<F: Field> BasicRlcChip<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
<<<<<<< HEAD
	let q_rlc = meta.selector();
	let q_mul = meta.selector();
	let val = meta.advice_column();
	let rlc = meta.advice_column_in(SecondPhase);

	meta.enable_equality(val);
	meta.enable_equality(rlc);
	
	let config = Self {
	    val,
	    rlc,
	    q_rlc,
	    q_mul,
	    _marker: PhantomData
	};

	config
=======
        let q_rlc = meta.selector();
        let q_mul = meta.selector();
        let cons = meta.fixed_column();
        let val = meta.advice_column();
        let rlc = meta.advice_column_in(SecondPhase);

        meta.enable_equality(val);
        meta.enable_equality(rlc);
        meta.enable_equality(cons);
        meta.enable_constant(cons);

        let config = Self { val, rlc, q_rlc, q_mul, _marker: PhantomData };

        config
>>>>>>> d81badaa03408ace3591b59a65d622cd27927ea7
    }

    pub fn create_gates(&self, meta: &mut ConstraintSystem<F>, gamma: Challenge) {
        meta.create_gate("RLC computation", |meta| {
            let sel = meta.query_selector(self.q_rlc);
            let val = meta.query_advice(self.val, Rotation::cur());
            let rlc_curr = meta.query_advice(self.rlc, Rotation::cur());
            let rlc_prev = meta.query_advice(self.rlc, Rotation::prev());
            let [gamma] = [gamma].map(|challenge| meta.query_challenge(challenge));

            vec![sel * (rlc_prev * gamma + val - rlc_curr)]
        });

        meta.create_gate("RLC mul", |meta| {
            let sel = meta.query_selector(self.q_mul);
            let a = meta.query_advice(self.rlc, Rotation::cur());
            let b = meta.query_advice(self.rlc, Rotation(1));
            let c = meta.query_advice(self.rlc, Rotation(2));
            let d = meta.query_advice(self.rlc, Rotation(3));

            vec![sel * (a + b * c - d)]
        });
    }
}

#[derive(Clone, Debug)]
pub struct RlcChip<F: Field> {
    pub basic_chips: Vec<BasicRlcChip<F>>,
    pub constants: Vec<Column<Fixed>>,
    pub challenge_id: Rc<String>,
    pub context_id: Rc<String>,
    pub gamma: Challenge,
    _marker: PhantomData<F>,
}

impl<F: Field> RlcChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        num_basic_chips: usize,
        num_fixed: usize,
        challenge_id: String,
        context_id: String,
    ) -> Self {
        let mut basic_chips = Vec::with_capacity(num_basic_chips);
        for idx in 0..num_basic_chips {
            let basic_chip = BasicRlcChip::configure(meta);
            basic_chips.push(basic_chip);
        }

        let [gamma] = [(); 1].map(|_| meta.challenge_usable_after(FirstPhase));
        for idx in 0..num_basic_chips {
            basic_chips[idx].create_gates(meta, gamma);
        }

        let mut constants = Vec::with_capacity(num_fixed);
        for idx in 0..num_fixed {
            let fixed = meta.fixed_column();
            meta.enable_equality(fixed);
            constants.push(fixed);
        }
        Self {
            basic_chips,
            constants,
            challenge_id: Rc::new(challenge_id),
            context_id: Rc::new(context_id),
            gamma,
            _marker: PhantomData,
        }
    }

    fn min_chip_idx(&self, ctx: &Context<'_, F>) -> usize {
        let advice_rows = ctx.advice_rows_get(&self.context_id);

        self.basic_chips
            .iter()
            .enumerate()
            .min_by(|(i, _), (j, _)| advice_rows[*i].cmp(&advice_rows[*j]))
            .map(|(i, _)| i)
            .expect(format!("Should exist basic chip").as_str())
    }

    pub fn assign_region(
        &self,
        ctx: &mut Context<'_, F>,
        rlc_inputs: &Vec<Option<QuantumCell<F>>>,
        val_inputs: &Vec<Option<QuantumCell<F>>>,
        rlc_offsets: Vec<usize>,
        gate_offsets: Vec<usize>,
        chip_idx: Option<usize>,
    ) -> Result<(Vec<Option<AssignedValue<F>>>, Vec<Option<AssignedValue<F>>>), Error> {
        assert_eq!(rlc_inputs.len(), val_inputs.len());

        let chip_idx = if let Some(id) = chip_idx { id } else { self.min_chip_idx(ctx) };
        let row_offset = ctx.advice_rows_get(&self.context_id)[chip_idx];

        let mut rlc_vec = Vec::with_capacity(rlc_inputs.len());
        let mut val_vec = Vec::with_capacity(val_inputs.len());
        for (idx, (rlc, val)) in rlc_inputs.iter().zip(val_inputs).enumerate() {
            let rlc_assigned_val = if let Some(rlc) = rlc {
                let rlc_assigned =
                    ctx.assign_cell(rlc.clone(), self.basic_chips[chip_idx].rlc, row_offset + idx)?;
                Some(AssignedValue::new(
                    rlc_assigned,
                    self.context_id.clone(),
                    chip_idx,
                    row_offset + idx,
                    1u8,
                ))
            } else {
                None
            };
            rlc_vec.push(rlc_assigned_val);

            let val_assigned_val = if let Some(val) = val {
                let val_assigned =
                    ctx.assign_cell(val.clone(), self.basic_chips[chip_idx].val, row_offset + idx)?;
                Some(AssignedValue::new(
                    val_assigned,
                    self.context_id.clone(),
                    chip_idx,
                    row_offset + idx,
                    0u8,
                ))
            } else {
                None
            };
            val_vec.push(val_assigned_val);
        }
        for idx in &rlc_offsets {
            self.basic_chips[chip_idx].q_rlc.enable(&mut ctx.region, row_offset + idx)?;
        }
        for idx in &gate_offsets {
            self.basic_chips[chip_idx].q_mul.enable(&mut ctx.region, row_offset + idx)?;
        }
        ctx.advice_rows_get_mut(&self.context_id)[chip_idx] += rlc_inputs.len();

        Ok((rlc_vec, val_vec))
    }

    pub fn assign_region_rlc(
        &self,
        ctx: &mut Context<'_, F>,
        rlc_inputs: &Vec<QuantumCell<F>>,
        rlc_offsets: Vec<usize>,
        gate_offsets: Vec<usize>,
        chip_idx: Option<usize>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let (rlc_vec_opt, val_vec_opt) = self.assign_region(
            ctx,
            &rlc_inputs.iter().map(|q| Some(q.clone())).collect(),
            &vec![None; rlc_inputs.len()],
            rlc_offsets,
            gate_offsets,
            chip_idx,
        )?;

        let rlc_vec = rlc_vec_opt.iter().map(|v| v.clone().unwrap()).collect();
        Ok(rlc_vec)
    }

    pub fn assign_region_rlc_and_val(
        &self,
        ctx: &mut Context<'_, F>,
        rlc_inputs: &Vec<QuantumCell<F>>,
        val_inputs: &Vec<QuantumCell<F>>,
        rlc_offsets: Vec<usize>,
        gate_offsets: Vec<usize>,
        chip_idx: Option<usize>,
    ) -> Result<(Vec<AssignedValue<F>>, Vec<AssignedValue<F>>), Error> {
        let (rlc_vec_opt, val_vec_opt) = self.assign_region(
            ctx,
            &rlc_inputs.iter().map(|q| Some(q.clone())).collect(),
            &val_inputs.iter().map(|q| Some(q.clone())).collect(),
            rlc_offsets,
            gate_offsets,
            chip_idx,
        )?;

        let rlc_vec = rlc_vec_opt.iter().map(|v| v.clone().unwrap()).collect();
        let val_vec = val_vec_opt.iter().map(|v| v.clone().unwrap()).collect();
        Ok((rlc_vec, val_vec))
    }

    pub fn assign_region_rlc_and_val_idx(
        &self,
        ctx: &mut Context<'_, F>,
        rlc_inputs: &Vec<QuantumCell<F>>,
        val_inputs: &Vec<(usize, QuantumCell<F>)>,
        rlc_offsets: Vec<usize>,
        gate_offsets: Vec<usize>,
        chip_idx: Option<usize>,
    ) -> Result<(Vec<AssignedValue<F>>, Vec<(usize, AssignedValue<F>)>), Error> {
        let mut val_inputs_opt = Vec::with_capacity(rlc_inputs.len());
        let mut val_idx = 0;
        for idx in 0..rlc_inputs.len() {
            let val_input = {
                if val_idx < val_inputs.len() && idx == val_inputs[val_idx].0 {
                    val_idx += 1;
                    Some(val_inputs[val_idx - 1].1.clone())
                } else {
                    None
                }
            };
            val_inputs_opt.push(val_input);
        }

        let (rlc_vec_opt, val_vec_opt) = self.assign_region(
            ctx,
            &rlc_inputs.iter().map(|q| Some(q.clone())).collect(),
            &val_inputs_opt,
            rlc_offsets,
            gate_offsets,
            chip_idx,
        )?;

        let rlc_vec = rlc_vec_opt.iter().map(|v| v.clone().unwrap()).collect();
        let mut val_vec = Vec::new();
        for idx in 0..rlc_inputs.len() {
            if let Some(v) = &val_vec_opt[idx] {
                val_vec.push((idx, v.clone()));
            }
        }

        Ok((rlc_vec, val_vec))
    }

    // assumes 0 <= len <= max_len
    pub fn compute_rlc(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        input: &Vec<AssignedValue<F>>,
        len: AssignedValue<F>,
        max_len: usize,
    ) -> Result<RlcTrace<F>, Error> {
        assert!(input.len() == max_len);
        let gamma = ctx.challenge_get(&self.challenge_id);

        let mut running_rlc = Value::known(F::from(0));
        let mut rlc_vals = Vec::new();
        for (idx, val) in input.iter().enumerate() {
            running_rlc = running_rlc * gamma + val.value();
            rlc_vals.push(Witness(running_rlc));
        }

        let (rlc_cells, val_cells) = self.assign_region_rlc_and_val(
            ctx,
            &rlc_vals,
            &input.iter().map(|x| Existing(&x)).collect(),
            (1..input.len()).collect(),
            vec![],
            None,
        )?;

        if input.len() > 0 {
            ctx.region
                .constrain_equal(rlc_cells[0].assigned.cell(), val_cells[0].assigned.cell())?;
        }

        let is_zero = range.is_zero(ctx, &len)?;
        let len_minus_one = range.gate.sub(ctx, &Existing(&len), &Constant(F::from(1)))?;
        let idx = range.gate.select(
            ctx,
            &Constant(F::from(0)),
            &Existing(&len_minus_one),
            &Existing(&is_zero),
        )?;

        let rlc_val_pre = {
            if input.len() == 0 {
                let zero = range.gate.load_zero(ctx)?;
                zero
            } else {
                let out = self.select_from_cells(ctx, range, &rlc_cells, &idx)?;
                out
            }
        };

        // | rlc_val | is_zero | rlc_val_pre | rlc_val_pre |
        let rlc_val_sel = self.assign_region_rlc(
            ctx,
            &vec![
                Witness(
                    rlc_val_pre.value().copied() * (Value::known(F::from(1)) - is_zero.value()),
                ),
                Existing(&is_zero),
                Existing(&rlc_val_pre),
                Existing(&rlc_val_pre),
            ],
            vec![],
            vec![0],
            None,
        )?;
        let rlc_val = rlc_val_sel[0].clone();

        let rlc_trace = RlcTrace { rlc_val: rlc_val, rlc_len: len, max_len: max_len };
        Ok(rlc_trace)
    }

    pub fn select_from_cells(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        cells: &Vec<AssignedValue<F>>,
        idx: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let ind_vec = range.gate.idx_to_indicator(ctx, &Existing(&idx), cells.len())?;
        let mut inputs = Vec::new();
        let mut gate_offsets = Vec::new();
        let mut running_sum = Value::known(F::from(0));
        for (idx, (cell, ind)) in cells.iter().zip(ind_vec.iter()).enumerate() {
            if idx == 0 {
                inputs.push(Constant(F::from(0)));
            }
            inputs.push(Existing(&cell));
            inputs.push(Existing(&ind));
            running_sum = running_sum + cell.value().copied() * ind.value().copied();
            inputs.push(Witness(running_sum));
            gate_offsets.push(3 * idx);
        }

        let acc_vec = self.assign_region_rlc(ctx, &inputs, vec![], gate_offsets, None)?;
        Ok(acc_vec[acc_vec.len() - 1].clone())
    }

    // Define the dynamic RLC: RLC(a, l) = \sum_{i = 0}^{l - 1} a_i r^{l - 1 - i}
    // * We have that:
    //     RLC(a || b, l_a + l_b) = RLC(a, l_a) * r^{l_a} + RLC(b, l_b).
    // * Prop: For sequences b^1, \ldots, b^k with l(b^i) = l_i and
    //     RLC(a, l) = RLC(b^1, l_1) * r^{l_1 + ... + l_{k - 1}}
    //                 + RLC(b^2, l_2) * r^{l_2 + ... + l_{k - 1}}
    //                 ... + RLC(b^k, l_k), and
    //     l = l_1 + ... + l_k,
    //   then a = b^1 || ... || b^k.
    // * Pf: View both sides as polynomials in r.
    //
    // Assumes:
    // * each tuple of the input is (RLC(a, l), l) for some sequence a_i of length l
    // * all rlc_len values have been range checked
    pub fn constrain_rlc_concat(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        rlc_and_len_inputs: &Vec<(AssignedValue<F>, AssignedValue<F>)>,
        max_lens: &Vec<usize>,
        concat: (AssignedValue<F>, AssignedValue<F>),
        max_len: usize,
        rlc_cache: &Vec<AssignedValue<F>>,
    ) -> Result<(), Error> {
        assert!(rlc_cache.len() >= log2(max_len));
        assert!(rlc_cache.len() >= log2(*max_lens.iter().max().unwrap()));

        let (_, _, len_sum) = range.gate.inner_product(
            ctx,
            &rlc_and_len_inputs.iter().map(|(a, b)| Constant(F::from(1))).collect(),
            &rlc_and_len_inputs.iter().map(|(a, b)| Existing(&b)).collect(),
        )?;
        range.gate.assert_equal(ctx, &Existing(&len_sum), &Existing(&concat.1))?;

        let mut gamma_pows = Vec::new();
        for (idx, (rlc, len)) in rlc_and_len_inputs.iter().enumerate() {
            let gamma_pow =
                self.rlc_pow(ctx, range, len.clone(), max(1, log2(max_lens[idx])), &rlc_cache)?;
            gamma_pows.push(gamma_pow);
        }

        let mut inputs = Vec::new();
        let mut intermed = Vec::new();
        let mut gate_offsets = Vec::new();
        for idx in 0..rlc_and_len_inputs.len() {
            if idx == 0 {
                inputs.push(Existing(&rlc_and_len_inputs[idx].0));
                intermed.push(rlc_and_len_inputs[idx].0.value().copied());
            } else {
                inputs.push(Existing(&rlc_and_len_inputs[idx].0));
                inputs.push(Witness(intermed[intermed.len() - 1]));
                inputs.push(Existing(&gamma_pows[idx]));
                inputs.push(Witness(
                    rlc_and_len_inputs[idx].0.value().copied()
                        + gamma_pows[idx].value().copied() * intermed[intermed.len() - 1],
                ));
                intermed.push(
                    rlc_and_len_inputs[idx].0.value().copied()
                        + gamma_pows[idx].value().copied() * intermed[intermed.len() - 1],
                );

                gate_offsets.push(4 * idx - 3);
            }
        }
        inputs.push(Constant(F::from(0)));
        inputs.push(Constant(F::from(0)));
        inputs.push(Existing(&concat.0));
        gate_offsets.push(4 * rlc_and_len_inputs.len() - 4);

        let rlc_concat = self.assign_region_rlc(ctx, &inputs, vec![], gate_offsets, None)?;

        for idx in 0..(rlc_and_len_inputs.len() - 1) {
            ctx.region.constrain_equal(
                rlc_concat[4 * idx].assigned.cell(),
                rlc_concat[4 * idx + 2].assigned.cell(),
            )?;
        }
        Ok(())
    }

    pub fn load_rlc_cache(
        &self,
        ctx: &mut Context<'_, F>,
        cache_bits: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let gamma = ctx.challenge_get(&self.challenge_id);

        let mut rlc_inputs = Vec::new();
        let mut val_inputs = vec![(1, Constant(F::from(0)))];
        let mut rlc_offsets = vec![1];
        let mut gate_offsets = Vec::new();
        let mut vals = Vec::new();
        for idx in 0..cache_bits {
            // rlc:   | 1 | g | 0 | g | g | g^2
            // val:   |   | 0 |   |
            // q_rlc: |   | 1 |   |
            // q_mul: |   |   | 1 |
            if idx == 0 {
                rlc_inputs.push(Constant(F::from(1)));
                rlc_inputs.push(Witness(*gamma));
                vals.push(*gamma);
            } else {
                rlc_inputs.push(Constant(F::from(0)));
                rlc_inputs.push(Witness(vals[vals.len() - 1]));
                rlc_inputs.push(Witness(vals[vals.len() - 1]));
                rlc_inputs.push(Witness(vals[vals.len() - 1] * vals[vals.len() - 1]));
                gate_offsets.push(4 * idx - 2);
                vals.push(vals[vals.len() - 1] * vals[vals.len() - 1]);
            }
        }

        let cache = self.assign_region_rlc_and_val_idx(
            ctx,
            &rlc_inputs,
            &val_inputs,
            rlc_offsets,
            gate_offsets,
            None,
        )?;
        for idx in 0..(cache_bits - 1) {
            ctx.region.constrain_equal(
                cache.0[4 * idx + 1].assigned.cell(),
                cache.0[4 * idx + 3].assigned.cell(),
            )?;
            ctx.region.constrain_equal(
                cache.0[4 * idx + 1].assigned.cell(),
                cache.0[4 * idx + 4].assigned.cell(),
            )?;
        }
        let mut ret = Vec::new();
        for idx in 0..cache_bits {
            ret.push(cache.0[4 * idx + 1].clone());
        }
        Ok(ret)
    }

    pub fn rlc_pow(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        pow: AssignedValue<F>,
        pow_bits: usize,
        rlc_cache: &Vec<AssignedValue<F>>,
    ) -> Result<AssignedValue<F>, Error> {
        assert!(pow_bits <= rlc_cache.len());

        let bits = range.num_to_bits(ctx, &pow, pow_bits)?;

        let mut inputs = Vec::new();
        let mut gate_offsets = Vec::new();
        for idx in 0..pow_bits {
            // prod = bit * x + (1 - bit)
            // | 1   | bit  | x | 1 + bit * x | bit | prod | 1 | bit + prod |
            inputs.push(Constant(F::from(1)));
            inputs.push(Existing(&bits[idx]));
            inputs.push(Existing(&rlc_cache[idx]));
            inputs.push(Witness(
                Value::known(F::from(1))
                    + bits[idx].value().copied() * rlc_cache[idx].value().copied(),
            ));
            gate_offsets.push(8 * idx);

            inputs.push(Existing(&bits[idx]));
            inputs.push(Witness(
                Value::known(F::from(1))
                    + bits[idx].value().copied() * rlc_cache[idx].value().copied()
                    - bits[idx].value().copied(),
            ));
            inputs.push(Constant(F::from(1)));
            inputs.push(Witness(
                Value::known(F::from(1))
                    + bits[idx].value().copied() * rlc_cache[idx].value().copied(),
            ));
            gate_offsets.push(8 * idx + 4);
        }

        // multi-exp of bits and rlc_cache
        let dot = self.assign_region_rlc(ctx, &inputs, vec![], gate_offsets, None)?;
        for idx in 0..pow_bits {
            ctx.region.constrain_equal(
                dot[8 * idx + 3].assigned.cell(),
                dot[8 * idx + 7].assigned.cell(),
            )?;
        }

        if pow_bits == 1 {
            Ok(dot[5].clone())
        } else {
            let mut inputs2 = Vec::new();
            let mut gate_offsets2 = Vec::new();
            let mut intermed = Vec::new();
            for idx in 0..(pow_bits - 1) {
                if idx == 0 {
                    inputs2.push(Constant(F::from(0)));
                    inputs2.push(Existing(&dot[5]));
                    inputs2.push(Existing(&dot[13]));
                    inputs2.push(Witness(dot[5].value().copied() * dot[13].value().copied()));
                    gate_offsets2.push(0);
                    intermed.push(dot[5].value().copied() * dot[13].value().copied());
                } else {
                    inputs2.push(Constant(F::from(0)));
                    inputs2.push(Existing(&dot[8 * (idx + 1) + 5]));
                    inputs2.push(Witness(intermed[intermed.len() - 1]));
                    inputs2.push(Witness(
                        dot[8 * (idx + 1) + 5].value().copied() * intermed[intermed.len() - 1],
                    ));
                    gate_offsets2.push(4 * idx);
                    intermed.push(
                        dot[8 * (idx + 1) + 5].value().copied() * intermed[intermed.len() - 1],
                    );
                }
            }
            let prods = self.assign_region_rlc(ctx, &inputs2, vec![], gate_offsets2, None)?;
            for idx in 0..(pow_bits - 2) {
                ctx.region.constrain_equal(
                    prods[4 * idx + 3].assigned.cell(),
                    prods[4 * idx + 6].assigned.cell(),
                )?;
            }
            Ok(prods[prods.len() - 1].clone())
        }
    }
}

#[derive(Clone, Debug)]
pub struct TestConfig<F: Field> {
    rlc: RlcChip<F>,
    range: RangeConfig<F>,
}

impl<F: Field> TestConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        num_basic_chips: usize,
        num_chip_fixed: usize,
        range_strategy: RangeStrategy,
        num_advice: &[usize],
        mut num_lookup_advice: &[usize],
        num_fixed: usize,
        lookup_bits: usize,
    ) -> Self {
        let rlc = RlcChip::configure(
            meta,
            num_basic_chips,
            num_chip_fixed,
            "gamma".to_string(),
            "rlc".to_string(),
        );
        let range = RangeConfig::configure(
            meta,
            range_strategy,
            num_advice,
            num_lookup_advice,
            num_fixed,
            lookup_bits,
            "default".to_string(),
        );
        Self { rlc, range }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TestCircuit<F> {
    inputs: Vec<u8>,
    len: usize,
    max_len: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = TestConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        TestConfig::configure(meta, 1, 1, Vertical, &[1], &[0], 1, 10)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.range.load_lookup_table(&mut layouter)?;

        let gamma = layouter.get_challenge(config.rlc.gamma);
        let using_simple_floor_planner = true;
        let mut first_pass = true;
        let rlc_trace = layouter.assign_region(
            || "load_inputs",
            |mut region| {
                if first_pass && using_simple_floor_planner {
                    first_pass = false;
                }
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![
                            ("default".to_string(), config.range.gate.num_advice),
                            ("rlc".to_string(), config.rlc.basic_chips.len()),
                        ],
                    },
                );
                let ctx = &mut aux;
                ctx.challenge.insert("gamma".to_string(), gamma);

                let inputs_assigned = config.range.gate.assign_region_smart(
                    ctx,
                    self.inputs.iter().map(|x| Witness(Value::known(F::from(*x as u64)))).collect(),
                    vec![],
                    vec![],
                    vec![],
                )?;
                let len_assigned = config.range.gate.assign_region_smart(
                    ctx,
                    vec![Witness(Value::known(F::from(self.len as u64)))],
                    vec![],
                    vec![],
                    vec![],
                )?;

                let rlc_trace = config.rlc.compute_rlc(
                    ctx,
                    &config.range,
                    &inputs_assigned,
                    len_assigned[0].clone(),
                    self.max_len,
                )?;

                let stats = config.range.finalize(ctx)?;
                Ok(rlc_trace)
            },
        )?;

        let real_rlc = gamma.map(|g| compute_rlc_acc(&self.inputs[..self.len].to_vec(), g));
        rlc_trace.rlc_val.value().zip(real_rlc).assert_if_known(|(a, b)| *a == b);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::rlp::rlc::{log2, TestCircuit};
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use std::marker::PhantomData;

    #[test]
    pub fn test_mock_rlc() {
        let k = 18;
        let input_bytes = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let max_len = input_bytes.len();
        let max_len_bits = log2(max_len);
        let len = 32;

        let circuit = TestCircuit::<Fr> { inputs: input_bytes, len, max_len, _marker: PhantomData };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    pub fn test_rlc() {}
}

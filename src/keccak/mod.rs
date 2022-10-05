#![allow(non_snake_case)]
// we implement Keccak without lookups using the custom gates found in https://blog.polygon.technology/zk-white-paper-efficient-zk-proofs-for-keccak/
// keccak python code reference: https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py
use halo2_base::{
    gates::{GateInstructions, RangeInstructions, range::{RangeConfig}},
    utils::{fe_to_biguint, value_to_option},
    AssignedValue, Context,
    QuantumCell::{self, Constant, Existing, Witness},
};
use halo2_proofs::{
    circuit::Value,
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use lazy_static::lazy_static;
use std::{marker::PhantomData, rc::Rc};

const LANE_LEN: usize = 64;
const ROUNDS: usize = 24;

lazy_static! {
    pub static ref RC: [u64; 24] = {
        let mut rc = [0; 24];
        let mut r = 1;
        for round in 0..24 {
            for j in 0..7 {
                r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256;
                if r & 2 != 0 {
                    rc[round] |= 1 << ((1 << j) - 1);
                }
            }
        }
        rc
    };
}

#[derive(Clone, Debug)]
pub struct KeccakChip<F: FieldExt> {
    pub keccak_f_chips: Vec<KeccakF1600Chip<F>>,
    pub constants: Vec<Column<Fixed>>,
    context_id: Rc<String>,
    rate: usize,
    // delimited_suffix: u8,
    output_bit_len: usize,
}

impl<F: FieldExt> KeccakChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        context_id: String,
        rate: usize,
        // delimited_suffix: u8,
        output_bit_len: usize,
        num_advice: usize,
        num_fixed: usize,
    ) -> Self {
        assert!(rate % 8 == 0);
        let num_chips = (num_advice + 63) / 64;
        println!(
            "Creating {} keccak_f chips, rounding total advice columns up to {}",
            num_chips,
            num_chips * 64
        );
        let constants = (0..num_fixed)
            .map(|_| {
                let f = meta.fixed_column();
                meta.enable_equality(f);
                f
            })
            .collect_vec();
        let context_id = Rc::new(context_id);
        let keccak_f_chips = (0..num_chips)
            .map(|i| KeccakF1600Chip::configure(meta, &context_id, i * 64))
            .collect_vec();

        Self {
            keccak_f_chips,
            constants,
            context_id,
            rate,
            // delimited_suffix,
            output_bit_len,
        }
    }

    pub fn pad_bits(
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	inputs: &Vec<AssignedValue<F>>,
	len: AssignedValue<F>,
	in_min_len: usize,
	in_max_len: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
	assert_eq!(in_max_len, inputs.len());
	assert_eq!(in_max_len % 8, 0);
	let out_len = ((in_max_len + 8 + 1087) / 1088) * 1088;

	let mut out_vec = Vec::new();
	for idx in 0..in_min_len {
	    out_vec.push(inputs[idx].clone());
	}
	let mut append: Vec<QuantumCell<F>> = (in_min_len..in_max_len).map(|idx| {
	    inputs[idx].value().zip(len.value()).map(|(v, l)| {
		if idx == usize::try_from(fe_to_biguint(l)).unwrap() {
		    F::one()
		} else if idx < usize::try_from(fe_to_biguint(l)).unwrap() {
		    *v
		} else {
		    F::zero()
		}
	    })
	}).map(|v| Witness(v)).collect();
	for idx in in_max_len..out_len {
	    if idx < out_len - 1 {
		append.push(Constant(F::zero()));
	    } else {
		append.push(Constant(F::one()));
	    }
	}
	let mut new_out_vec = range.gate.assign_region_smart(ctx, append, vec![], vec![], vec![])?;
	out_vec.append(&mut new_out_vec);
	
	// check matches up to len
	let mut is_equal_vec = Vec::new();
	for idx in in_min_len..in_max_len {
	    let is_equal = range.is_equal(ctx, &Existing(&inputs[idx]), &Existing(&out_vec[idx]))?;
	    is_equal_vec.push(is_equal);		
	}

	let mut cumulative_inputs = Vec::new();
	let mut cumulative_gates = Vec::new();
	let mut sum = is_equal_vec[0].value().copied();
	cumulative_inputs.push(Existing(&is_equal_vec[0]));
	for idx in (in_min_len + 1)..in_max_len {
	    cumulative_gates.push(3 * idx - 3);
	    cumulative_inputs.push(Constant(F::one()));
	    cumulative_inputs.push(Existing(&is_equal_vec[idx - in_min_len]));
	    sum = sum + is_equal_vec[idx - in_min_len].value();
	    cumulative_inputs.push(Witness(sum));
	}
	let vals = range.gate.assign_region_smart(
	    ctx, cumulative_inputs, cumulative_gates, vec![], vec![],
	)?;
	let len_minus_min_val = len.value().copied() - Value::known(F::from(in_min_len as u64));
	let val = range.gate.assign_region_smart(
	    ctx,
	    vec![Witness(len_minus_min_val),
		 Constant(F::one()),
		 Constant(F::from(in_min_len as u64)),
		 Existing(&len)],
	    vec![0], vec![], vec![]
	)?;
	let len_minus_min_assigned = val[0].clone();
	let is_equal_sum = range.gate.select_from_idx(
	    ctx,
	    &(0..in_max_len-in_min_len).map(|idx| Existing(&vals[3 * idx])).collect(),
	    &Existing(&len_minus_min_assigned),
	)?;
	range.gate.assert_equal(ctx, &Existing(&is_equal_sum), &Existing(&len_minus_min_assigned))?;

	// check padding val at index `len`
	let idx_len_val = range.gate.select_from_idx(
	    ctx,
	    &out_vec[in_min_len..in_max_len].iter().map(|v| Existing(v)).collect(),
	    &Existing(&len)
	)?;
	range.gate.assert_equal(ctx, &Existing(&idx_len_val), &Constant(F::from(1)))?;
	
	// check padding 0s after index `len`
	let mut is_zero_vec = Vec::new();
	for idx in in_min_len..in_max_len {
	    let is_zero = range.is_zero(ctx, &out_vec[idx])?;
	    is_zero_vec.push(is_zero);		
	}
	let mut cumulative_inputs2 = Vec::new();
	let mut cumulative_gates2 = Vec::new();
	let mut sum2 = is_zero_vec[in_max_len - in_min_len - 1].value().copied();
	cumulative_inputs2.push(Existing(&is_zero_vec[in_max_len - in_min_len - 1]));
	for idx in (in_min_len + 1)..in_max_len {
	    cumulative_gates2.push(3 * idx - 3);
	    cumulative_inputs2.push(Constant(F::one()));
	    cumulative_inputs2.push(Existing(&is_zero_vec[in_max_len - in_min_len - 1 - idx]));
	    sum2 = sum2 + is_zero_vec[in_max_len - in_min_len - 1 - idx].value().copied();
	    cumulative_inputs2.push(Witness(sum2));
	}
	let vals2 = range.gate.assign_region_smart(
	    ctx, cumulative_inputs2, cumulative_gates2, vec![], vec![],
	)?;
	let max_minus_len_val = Value::known(F::from(in_max_len as u64)) - len.value().copied();
	let val2 = range.gate.assign_region_smart(
	    ctx,
	    vec![Witness(max_minus_len_val),
		 Constant(F::one()),
		 Existing(&len),
		 Constant(F::from(in_max_len as u64))],
	    vec![0], vec![], vec![]
	)?;
	let max_minus_len_assigned = val2[0].clone();
	let is_zero_sum = range.gate.select_from_idx(
	    ctx,
	    &(0..in_max_len-in_min_len).map(|idx| Existing(&vals2[3 * idx])).collect(),
	    &Existing(&max_minus_len_assigned),
	)?;
	range.gate.assert_equal(ctx, &Existing(&is_zero_sum), &Existing(&max_minus_len_assigned))?;

	assert_eq!(out_len, out_vec.len());
	Ok(out_vec)
    }    

    pub fn keccak(
        &self,
        ctx: &mut Context<'_, F>,
        mut input_bits: Vec<QuantumCell<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        // === Padding ===
        input_bits.push(Constant(F::one()));
        while input_bits.len() % self.rate != self.rate - 1 {
            input_bits.push(Constant(F::zero()));
        }
        input_bits.push(Constant(F::one()));

        self.keccak_fully_padded(ctx, input_bits)
    }

    pub fn keccak_fully_padded(
        &self,
        ctx: &mut Context<'_, F>,
        input_bits: Vec<QuantumCell<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        // === Absorb all the inputs blocks ===
        let mut state_bits: Option<Vec<AssignedValue<F>>> = None;
        let mut chip_id = ctx.min_gate_index(&self.context_id);
        let mut lanes = None;
        for block in input_bits.chunks(self.rate) {
            let mut state_lanes = if let Some(state) = state_bits {
                self.keccak_f_chips[chip_id].absorb(ctx, &state, block, false).unwrap()
            } else {
                self.keccak_f_chips[chip_id].load_1600bits_to_lanes(ctx, block).unwrap()
            };
            if block.len() == self.rate {
                state_lanes = self.keccak_f_chips[chip_id].keccak_f1600(ctx, state_lanes, false)?;
            }
            chip_id = ctx.min_gate_index(&self.context_id);
            state_bits = Some(
                self.keccak_f_chips[chip_id].store_lanes_to_1600bits(ctx, &state_lanes).unwrap(),
            );
            lanes = Some(state_lanes);
        }

        // === Squeeze phase ===
        let mut output = Vec::with_capacity(self.output_bit_len);
        let mut state_lanes = lanes.unwrap();
        let mut state_bits = state_bits.unwrap();
        while output.len() < self.output_bit_len {
            let block_size = std::cmp::min(self.output_bit_len - output.len(), self.rate);
            output.extend(state_bits[..block_size].iter().map(|a| a.clone()));
            if output.len() < self.output_bit_len {
                chip_id = ctx.min_gate_index(&self.context_id);
                state_lanes =
                    self.keccak_f_chips[chip_id].keccak_f1600(ctx, state_lanes, true).unwrap();
                state_bits = self.keccak_f_chips[chip_id]
                    .store_lanes_to_1600bits(ctx, &state_lanes)
                    .unwrap();
            }
        }

        Ok(output)
    }
}

#[derive(Clone, Debug)]
pub struct KeccakF1600Chip<F: FieldExt> {
    // we will represent each 64-bit word as a single row
    pub values: [Column<Advice>; LANE_LEN],
    pub context_id: Rc<String>,
    pub q_rounds: Column<Fixed>, // turns on all 24 rounds
    pub q_absorb: Selector,
    pub q_bits_to_lanes: Selector,
    pub q_lanes_to_bits: Selector,
    pub q_check_bits: Selector,
    pub q_c_cp: Selector,
    pub q_d: Selector,
    // pub q_batch_xor: Selector,
    column_offset: usize,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> KeccakF1600Chip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        context_id: &Rc<String>,
        column_offset: usize,
    ) -> Self {
        let values = (0..LANE_LEN)
            .map(|_| {
                let a = meta.advice_column();
                meta.enable_equality(a);
                a
            })
            .collect_vec()
            .try_into()
            .unwrap();

        let config = Self {
            values,
            context_id: context_id.clone(),
            q_rounds: meta.fixed_column(),
            q_absorb: meta.selector(),
            q_bits_to_lanes: meta.selector(),
            q_lanes_to_bits: meta.selector(),
            q_check_bits: meta.selector(),
            q_c_cp: meta.selector(),
            q_d: meta.selector(),
            column_offset,
            _marker: PhantomData,
        };
        for round in 0..ROUNDS {
            config.create_keccak_f_round_gate(meta, round);
        }

        meta.create_gate("absorb 1600 bits and convert to 64bit lanes", |meta| {
            let state_bits: Vec<Vec<Expression<F>>> = (0..25)
                .map(|x| {
                    config
                        .values
                        .iter()
                        .map(|column| meta.query_advice(*column, Rotation(x as i32)))
                        .collect_vec()
                })
                .collect_vec();
            let input_bits: Vec<Vec<Expression<F>>> = (0..25)
                .map(|x| {
                    config
                        .values
                        .iter()
                        .map(|column| meta.query_advice(*column, Rotation(x as i32 + 25)))
                        .collect_vec()
                })
                .collect_vec();
            let q = meta.query_selector(config.q_absorb);
            (0..25)
                .map(|x| {
                    q.clone()
                        * (meta.query_advice(config.values[x], Rotation(50))
                            - bits_to_num(
                                (0..64).map(|i| xor(&state_bits[x][i], &input_bits[x][i])),
                            ))
                })
                .collect_vec()
        });

        meta.create_gate("convert 1600 bits to 64bit lanes", |meta| {
            let state_bits: Vec<Vec<Expression<F>>> = (0..25)
                .map(|x| {
                    config
                        .values
                        .iter()
                        .map(|column| meta.query_advice(*column, Rotation(x as i32)))
                        .collect_vec()
                })
                .collect_vec();
            let q = meta.query_selector(config.q_bits_to_lanes);
            (0..25)
                .map(|x| {
                    q.clone()
                        * (meta.query_advice(config.values[x], Rotation(25))
                            - bits_to_num(state_bits[x].clone()))
                })
                .collect_vec()
        });

        meta.create_gate("convert 64bit lanes to 1600 bits", |meta| {
            let q = meta.query_selector(config.q_lanes_to_bits);
            let lanes =
                (0..25).map(|i| meta.query_advice(config.values[i], Rotation::cur())).collect_vec();
            let bits: Vec<Vec<Expression<F>>> = (0..25)
                .map(|x| {
                    config
                        .values
                        .iter()
                        .map(|column| meta.query_advice(*column, Rotation(x as i32 + 1)))
                        .collect_vec()
                })
                .collect_vec();

            let mut constraints = Vec::new();
            constraints.extend(
                (0..25).map(|x| q.clone() * (lanes[x].clone() - bits_to_num(bits[x].clone()))),
            );
            constraints
        });

        config
    }

    pub fn load_1600bits_to_lanes(
        &self,
        ctx: &mut Context<'_, F>,
        bits: &[QuantumCell<F>],
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let row_offset = self.get_row_offset(ctx);
        self.q_bits_to_lanes.enable(&mut ctx.region, row_offset)?;
        let bits = [bits, &(bits.len()..1600).map(|_| Constant(F::zero())).collect_vec()].concat();
        let lanes = (0..25)
            .map(|x| {
                bits[(64 * x)..(64 * x + 64)]
                    .iter()
                    .enumerate()
                    .fold(Value::known(0u64), |acc, (i, x)| {
                        acc + x.value().map(|x| (x.get_lower_32() as u64) << i)
                    })
                    .map(|x| F::from(x))
            })
            .collect_vec();
        let row_offset = self.get_row_offset(ctx);
        for i in 0..25 {
            self.q_check_bits.enable(&mut ctx.region, row_offset + i)?;
        }
        for chunk in bits.chunks(64) {
            self.assign_row_silent(ctx, chunk.iter().map(|x| x.clone()).collect_vec())?;
        }
        self.assign_row(ctx, lanes.into_iter().map(|v| Witness(v.clone())))
    }

    pub fn store_lanes_to_1600bits(
        &self,
        ctx: &mut Context<'_, F>,
        lanes: &[AssignedValue<F>],
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let row_offset = self.get_row_offset(ctx);
        self.q_lanes_to_bits.enable(&mut ctx.region, row_offset)?;
        assert_eq!(lanes.len(), 25);
        self.assign_row(ctx, lanes.iter().map(|a| Existing(a)).collect_vec())?;
        let mut output = Vec::with_capacity(1600);
        for lane in lanes {
            output.extend(
                self.assign_row(
                    ctx,
                    (0..64)
                        .map(|i| {
                            lane.value().map(|x| F::from(((x.get_lower_128() as u64) >> i) & 1))
                        })
                        .map(|v| Witness(v)),
                )
                .unwrap(),
            );
        }
        Ok(output)
    }

    pub fn absorb(
        &self,
        ctx: &mut Context<'_, F>,
        state_bits: &[AssignedValue<F>],
        input_bits: &[QuantumCell<F>],
        assign_state: bool,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert_eq!(state_bits.len(), 1600);
        assert!(input_bits.len() <= 1600);

        let input =
            [input_bits, &(input_bits.len()..1600).map(|_| Constant(F::zero())).collect_vec()]
                .concat();

        let row_offset = self.get_row_offset(ctx);
        if assign_state {
            self.q_absorb.enable(&mut ctx.region, row_offset)?;
            for word in &state_bits.iter().chunks(64) {
                self.assign_row_silent(ctx, word.map(|a| Existing(a)))?;
            }
        } else {
            self.q_absorb.enable(&mut ctx.region, row_offset - 25)?;
        }
        for word in &input.iter().chunks(64) {
            self.assign_row_silent(ctx, word.map(|x| x.clone()).collect_vec())?;
        }
        self.assign_row(
            ctx,
            (0..25)
                .map(|idx| {
                    state_bits[idx * 64..idx * 64 + 64]
                        .iter()
                        .zip(input[idx * 64..idx * 64 + 64].iter())
                        .enumerate()
                        .fold(Value::known(0u64), |acc, (i, (x, y))| {
                            acc + x
                                .value()
                                .zip(y.value())
                                .map(|(x, y)| ((x.get_lower_32() ^ y.get_lower_32()) as u64) << i)
                        })
                        .map(|x| F::from(x))
                })
                .map(|v| Witness(v))
                .collect_vec(),
        )
    }

    /// returns lanes and updates row_offset to new offset
    pub fn keccak_f1600(
        &self,
        ctx: &mut Context<'_, F>,
        mut lanes: Vec<AssignedValue<F>>,
        assign_input: bool,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        ctx.region.assign_fixed(
            || "keccak_f1600",
            self.q_rounds,
            self.get_row_offset(ctx) - 1 + assign_input as usize,
            || Value::known(F::one()),
        )?;
        for round in 0..ROUNDS {
            lanes =
                self.keccak_f1600_round(ctx, &lanes, round, assign_input || (round != 0)).unwrap();
        }
        Ok(lanes)
    }

    fn create_keccak_f_round_gate(&self, meta: &mut ConstraintSystem<F>, round: usize) {
        // We closely follow PolygonZero's paper, except that since our field F is >64 bits, we can use 64-bit packed words instead of 32-bit packed words
        // In these comments, `A` will mean bold A in their paper (so A[x,y] means the 64-bit word in lane (x,y)), `a` will mean non-bold A (so a[x,y,z] means the z-th bit of A[x,y])

        // This gate will constrain one round of keccak-f[1600]
        // The gate will access all cells in a 64 column by 37 row matrix:
        // 0: The inputs A[0..5, 0..5] and outputs A''[0..5, 0..5], A'''[0,0] -- 51 values in total, are all in the first row
        // 1: a''[0,0,0..64] takes up one row
        // 2..27: Each of a'[x,y,0..64] takes up one row
        // 27..32: Each of c'[x,0..64] takes up one row
        // 32..37: Each of c[x,0..64] takes up one row for each x

        meta.create_gate("check all 64 cells in row are bits", |meta| {
            let q = meta.query_selector(self.q_check_bits);
            self.values
                .iter()
                .map(|column| {
                    let a = meta.query_advice(*column, Rotation::cur());
                    q.clone() * is_bit(&a)
                })
                .collect_vec()
        });

        meta.create_gate("check d", |meta| {
            let q = meta.query_selector(self.q_d);
            let mut constraints: Vec<Expression<F>> = Vec::new();
            let ap: Vec<Vec<Vec<Expression<F>>>> = (0..5)
                .map(|x| {
                    (0..5)
                        .map(|y| {
                            self.values
                                .iter()
                                .map(|column| {
                                    meta.query_advice(column.clone(), Rotation((x + 5 * y) as i32))
                                })
                                .collect_vec()
                        })
                        .collect_vec()
                })
                .collect_vec();

            let cp: Vec<Vec<Expression<F>>> = (0..5)
                .map(|x| {
                    self.values
                        .iter()
                        .map(|column| meta.query_advice(column.clone(), Rotation((25 + x) as i32)))
                        .collect_vec()
                })
                .collect_vec();
            for x in 0..5 {
                for z in 0..64 {
                    let d: Expression<F> = (0..5)
                        .map(|i| ap[x][i][z].clone())
                        .fold(Expression::Constant(F::from(0)), |acc, a| acc + a)
                        - cp[x][z].clone();
                    constraints.push(
                        d.clone()
                            * (d.clone() - Expression::Constant(F::from(2)))
                            * (d - Expression::Constant(F::from(4))),
                    );
                }
            }
            constraints.into_iter().map(|expression| q.clone() * expression).collect_vec()
        });

        meta.create_gate("check relation between c and c'", |meta| {
            // let q = meta.query_fixed(self.q_rounds, Rotation(-(round as i32) * 37 - 27));
            let q = meta.query_selector(self.q_c_cp);
            let mut constraints: Vec<Expression<F>> = Vec::new();

            let c: Vec<Vec<Expression<F>>> = (0..5)
                .map(|x| {
                    self.values
                        .iter()
                        .map(|column| meta.query_advice(column.clone(), Rotation((5 + x) as i32)))
                        .collect_vec()
                })
                .collect_vec();

            let cp: Vec<Vec<Expression<F>>> = (0..5)
                .map(|x| {
                    self.values
                        .iter()
                        .map(|column| meta.query_advice(column.clone(), Rotation(x as i32)))
                        .collect_vec()
                })
                .collect_vec();
            for x in 0..5 {
                for z in 0..64 {
                    constraints.push(
                        xor3(&c[x][z], &c[(x + 4) % 5][z], &c[(x + 1) % 5][(z + 63) % 64])
                            - cp[x][z].clone(),
                    );
                }
            }
            constraints.into_iter().map(|expression| q.clone() * expression).collect_vec()
        });

        meta.create_gate("one round of keccak-f[1600]", |meta| {
            let q = meta.query_fixed(self.q_rounds, Rotation(-(round as i32) * 37));
            let A: Vec<Vec<Expression<F>>> = (0..5)
                .map(|x| {
                    (0..5)
                        .map(|y| meta.query_advice(self.values[x + 5 * y], Rotation::cur()))
                        .collect_vec()
                })
                .collect_vec();
            // App = A'', Appp = A''', ap = a', cp = c'
            let App: Vec<Vec<Expression<F>>> = (0..5)
                .map(|x| {
                    (0..5)
                        .map(|y| meta.query_advice(self.values[25 + x + 5 * y], Rotation::cur()))
                        .collect_vec()
                })
                .collect_vec();

            let Appp_00 = meta.query_advice(self.values[50], Rotation::cur());

            let app_00: Vec<Expression<F>> = self
                .values
                .iter()
                .map(|column| meta.query_advice(column.clone(), Rotation(1)))
                .collect_vec();

            let ap: Vec<Vec<Vec<Expression<F>>>> = (0..5)
                .map(|x| {
                    (0..5)
                        .map(|y| {
                            self.values
                                .iter()
                                .map(|column| {
                                    meta.query_advice(
                                        column.clone(),
                                        Rotation((2 + x + 5 * y) as i32),
                                    )
                                })
                                .collect_vec()
                        })
                        .collect_vec()
                })
                .collect_vec();

            let c: Vec<Vec<Expression<F>>> = (0..5)
                .map(|x| {
                    self.values
                        .iter()
                        .map(|column| meta.query_advice(column.clone(), Rotation((32 + x) as i32)))
                        .collect_vec()
                })
                .collect_vec();

            let cp: Vec<Vec<Expression<F>>> = (0..5)
                .map(|x| {
                    self.values
                        .iter()
                        .map(|column| meta.query_advice(column.clone(), Rotation((27 + x) as i32)))
                        .collect_vec()
                })
                .collect_vec();

            let mut constraints: Vec<Expression<F>> = Vec::new();

            // a[x,y,z] == a'[x,y,z] xor c[x,z] xor c'[x,z]
            for x in 0..5 {
                for y in 0..5 {
                    constraints.push(
                        A[x][y].clone()
                            - bits_to_num((0..64).map(|z| xor3(&ap[x][y][z], &c[x][z], &cp[x][z]))),
                    );
                }
            }

            // verifying computation of A''
            let mut r = vec![vec![0; 5]; 5];
            {
                let (mut x, mut y) = (1, 0);
                for t in 0..24 {
                    (x, y) = (y, (2 * x + 3 * y) % 5);
                    r[x][y] = ((t + 1) * (t + 2) / 2) % 64;
                    // note this does not match the r[x,y] in https://keccak.team/keccak_specs_summary.html#rotationOffsets
                    // ours equals r[y, 2x+3y] of loc cit.
                }
            }
            // (x,y) -> (3y+x, x) is the inverse transformation to (x,y) -> (y, 2x+3y) all mod 5
            // B[x,y] = rol(A'[3y+x,x], r[x][y]), using our definition of r[x][y]
            for x in 0..5 {
                for y in 0..5 {
                    constraints.push(
                        bits_to_num((0..64).map(|z| {
                            xorandn(
                                &ap[(3 * y + x) % 5][x][(z + 64 - r[x][y]) % 64],
                                &ap[(3 * y + x + 1) % 5][(x + 1) % 5]
                                    [(z + 64 - r[(x + 1) % 5][y]) % 64],
                                &ap[(3 * y + x + 2) % 5][(x + 2) % 5]
                                    [(z + 64 - r[(x + 2) % 5][y]) % 64],
                            )
                        })) - App[x][y].clone(),
                    );
                }
            }

            // check a''[0][0][0..64] is actually the bit representation of A''[0][0]
            constraints.push(bits_to_num(app_00.clone()) - App[0][0].clone());

            // verifying computation of A'''
            constraints.push(
                bits_to_num((0..64).map(|i| {
                    xor(&app_00[i], &Expression::Constant(F::from(((RC[round] >> i) & 1) as u64)))
                })) - Appp_00.clone(),
            );
            constraints.into_iter().map(|expression| q.clone() * expression).collect_vec()
        })
    }

    pub fn keccak_f1600_round(
        &self,
        ctx: &mut Context<'_, F>,
        lanes: &[AssignedValue<F>],
        round: usize,
        assign_input: bool,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert_eq!(lanes.len(), 25);
        let mut App = vec![vec![Value::unknown(); 5]; 5];
        let mut Appp_00 = Value::unknown();
        let mut c = [[Value::unknown(); 64]; 5];
        let mut cp = [[Value::unknown(); 64]; 5];
        let mut ap = [[[Value::unknown(); 64]; 5]; 5];
        let mut app_00 = [Value::unknown(); 64];

        // only do actual keccak computation if values are not None
        if lanes.iter().all(|lane| value_to_option(lane.value()).is_some()) {
            let mut A = [[0; 5]; 5];
            for x in 0..5 {
                for y in 0..5 {
                    A[x][y] =
                        value_to_option(lanes[x + 5 * y].value()).unwrap().get_lower_128() as u64;
                }
            }
            // θ
            let C = (0..5).map(|x| A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]).collect_vec();
            // A becomes A':
            for x in 0..5 {
                let d = C[(x + 4) % 5] ^ rol64(C[(x + 1) % 5], 1);
                for y in 0..5 {
                    A[x][y] = A[x][y] ^ d;
                }
            }
            let Ap = A.clone();
            // ρ and π
            // A becomes B:
            {
                let (mut x, mut y) = (1, 0);
                let mut current = A[x][y];
                for t in 0..24 {
                    (x, y) = (y, (2 * x + 3 * y) % 5);
                    (current, A[x][y]) = (A[x][y], rol64(current, (t + 1) * (t + 2) / 2));
                }
            }
            // χ
            let mut App_u64 = [[0; 5]; 5];
            for x in 0..5 {
                for y in 0..5 {
                    App_u64[x][y] = A[x][y] ^ ((!A[(x + 1) % 5][y]) & A[(x + 2) % 5][y]);
                }
            }
            Appp_00 = Value::known(F::from(App_u64[0][0] ^ RC[round]));
            for x in 0..5 {
                for y in 0..5 {
                    App[x][y] = Value::known(F::from(App_u64[x][y]));

                    (0..64).fold(Ap[x][y], |bits, i| {
                        ap[x][y][i] = Value::known(F::from(bits & 1));
                        bits >> 1
                    });
                }
                (0..64).fold(C[x], |bits, i| {
                    c[x][i] = Value::known(F::from(bits & 1));
                    bits >> 1
                });
                (0..64).fold(C[x] ^ C[(x + 4) % 5] ^ rol64(C[(x + 1) % 5], 1), |bits, i| {
                    cp[x][i] = Value::known(F::from(bits & 1));
                    bits >> 1
                });
            }
            (0..64).fold(App_u64[0][0], |bits, i| {
                app_00[i] = Value::known(F::from(bits & 1));
                bits >> 1
            });
        }
        if !assign_input {
            *self.get_row_offset_mut(ctx) -= 1;
        }
        let row_offset = self.get_row_offset(ctx);
        // check entries of a''[0][0][0..64] are bits
        // check a'[x,y,z] are all bits
        // check all entries of c are bits
        for i in (1..27).chain(32..37) {
            self.q_check_bits.enable(&mut ctx.region, row_offset + i)?;
        }
        self.q_c_cp.enable(&mut ctx.region, row_offset + 27)?;
        self.q_d.enable(&mut ctx.region, row_offset + 2)?;

        let mut output = Vec::with_capacity(25);
        let phase = ctx.current_phase();
        output.push(ctx.assign_cell(
            Witness(Appp_00),
            self.values[50],
            &self.context_id,
            self.column_offset + 50,
            row_offset,
            phase,
        )?);
        if assign_input {
            for x in 0..5 {
                for y in 0..5 {
                    ctx.assign_cell(
                        Existing(&lanes[x + 5 * y]),
                        self.values[x + 5 * y],
                        &self.context_id,
                        self.column_offset + x + 5 * y,
                        row_offset,
                        phase,
                    )?;
                }
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                let assigned = ctx.assign_cell(
                    Witness(App[x][y].clone()),
                    self.values[25 + x + 5 * y],
                    &self.context_id,
                    self.column_offset + 25 + x + 5 * y,
                    row_offset,
                    phase,
                )?;
                if x + 5 * y != 0 {
                    output.push(assigned);
                }
            }
        }
        *self.get_row_offset_mut(ctx) += 1;
        self.assign_row_silent(ctx, app_00.into_iter().map(|v| Witness(v)))?;
        for y in 0..5 {
            for x in 0..5 {
                self.assign_row_silent(ctx, ap[x][y].into_iter().map(|v| Witness(v)))?;
            }
        }
        for c_row in cp.into_iter() {
            self.assign_row_silent(ctx, c_row.into_iter().map(|v| Witness(v)))?;
        }
        for c_row in c.into_iter() {
            self.assign_row_silent(ctx, c_row.into_iter().map(|v| Witness(v)))?;
        }

        Ok(output)
    }

    fn get_row_offset(&self, ctx: &Context<'_, F>) -> usize {
        ctx.advice_rows_get(&self.context_id)[self.column_offset / 64]
    }

    fn get_row_offset_mut<'a>(&self, ctx: &'a mut Context<'_, F>) -> &'a mut usize {
        &mut ctx.advice_rows_get_mut(&self.context_id)[self.column_offset / 64]
    }

    pub fn assign_row_silent<'a, I>(&self, ctx: &mut Context<'_, F>, inputs: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = QuantumCell<'a, F>>,
    {
        let row_offset = self.get_row_offset(ctx);
        for (i, input) in inputs.into_iter().enumerate() {
            ctx.assign_cell(
                input,
                self.values[i],
                &self.context_id,
                self.column_offset + i,
                row_offset,
                ctx.current_phase(),
            )?;
        }
        *self.get_row_offset_mut(ctx) += 1;
        Ok(())
    }

    pub fn assign_row<'a, I>(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: I,
    ) -> Result<Vec<AssignedValue<F>>, Error>
    where
        I: IntoIterator<Item = QuantumCell<'a, F>>,
    {
        let row_offset = self.get_row_offset(ctx);
        let output = inputs
            .into_iter()
            .enumerate()
            .map(|(i, input)| {
                ctx.assign_cell(
                    input,
                    self.values[i],
                    &self.context_id,
                    self.column_offset + i,
                    row_offset,
                    ctx.current_phase(),
                )
                .unwrap()
            })
            .collect_vec();
        *self.get_row_offset_mut(ctx) += 1;
        Ok(output)
    }
}

#[inline]
fn rol64(a: u64, n: usize) -> u64 {
    (a >> (64 - (n % 64))) + (a << (n % 64))
}

/// only works for up to 64-bits
pub fn bits_to_num<F>(bits: impl IntoIterator<Item = Expression<F>>) -> Expression<F>
where
    F: FieldExt,
{
    bits.into_iter().enumerate().fold(Expression::Constant(F::from(0)), |acc, (i, bit)| {
        acc + Expression::Constant(F::from(1u64 << i)) * bit
    })
}

pub fn is_bit<F>(x: &Expression<F>) -> Expression<F>
where
    F: FieldExt,
{
    x.clone() * x.clone() - x.clone()
}

pub fn xor<F>(x: &Expression<F>, y: &Expression<F>) -> Expression<F>
where
    F: FieldExt,
{
    // x + y - 2 * x * y
    x.clone() + y.clone() - Expression::Constant(F::from(2)) * x.clone() * y.clone()
}

pub fn xor3<F>(x: &Expression<F>, y: &Expression<F>, z: &Expression<F>) -> Expression<F>
where
    F: FieldExt,
{
    // x + y + z − 2(xy + xz + yz) + 4xyz
    x.clone() + y.clone() + z.clone()
        - Expression::Constant(F::from(2))
            * (x.clone() * y.clone() + x.clone() * z.clone() + y.clone() * z.clone())
        + Expression::Constant(F::from(4)) * x.clone() * y.clone() * z.clone()
}

pub fn xorandn<F>(x: &Expression<F>, y: &Expression<F>, z: &Expression<F>) -> Expression<F>
where
    F: FieldExt,
{
    // x + z − yz − 2xz + 2xyz
    x.clone() + z.clone()
        - y.clone() * z.clone()
        - Expression::Constant(F::from(2))
            * (x.clone() * z.clone() - x.clone() * y.clone() * z.clone())
}

#[cfg(test)]
pub(crate) mod tests;

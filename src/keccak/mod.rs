use hex::encode;
use halo2_base::{
    gates::{GateInstructions, RangeInstructions, range::{RangeConfig}},
    utils::{fe_to_biguint, value_to_option},
    AssignedValue, Context,
    QuantumCell::{self, Constant, Existing, Witness},
};
use halo2_proofs::{
    halo2curves::FieldExt,
    circuit::Value,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, rc::Rc};
use crate::rlp::rlc::log2;

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
    pub static ref ROTATION_OFFSET: [[usize; 5]; 5] = {
        let mut r = [[0; 5]; 5];
        let (mut x, mut y) = (1, 0);
        for t in 0..24 {
            r[x][y] = ((t + 1) * (t + 2) / 2) % 64;
            (x, y) = (y, (2 * x + 3 * y) % 5);
        }
        r
    };
}

pub fn print_bytes<F: FieldExt>(tag: String, x: &[AssignedValue<F>]) {
    let asdf: Vec<Value<F>> = x.iter().map(|a| a.value().copied()).collect();
    let asdf2: Value<Vec<F>> = Value::from_iter::<Vec<Value<F>>>(asdf);
    let asdf3: Value<Vec<u8>> = asdf2.map(|a|
	a.iter().map(|b| { u8::try_from(fe_to_biguint(b)).unwrap() }).collect()
    );
    println!("{:?} {:?}", tag, asdf3.map(|a| encode(a)));
}

pub fn print_bytes_raw<F: FieldExt>(tag: String, x: &[AssignedValue<F>]) {
    let asdf: Vec<Value<F>> = x.iter().map(|a| a.value().copied()).collect();
    let asdf2: Value<Vec<F>> = Value::from_iter::<Vec<Value<F>>>(asdf);
    let asdf3: Value<Vec<u8>> = asdf2.map(|a|
	a.iter().map(|b| { u8::try_from(fe_to_biguint(b)).unwrap() }).collect()
    );
    println!("{:?} {:?}", tag, asdf3);
}

pub fn print_bits<F: FieldExt>(tag: String, x: &[AssignedValue<F>]) {
    let asdf: Vec<Value<F>> = x.iter().map(|a| a.value().copied()).collect();
    print_bits_val(tag, &asdf[..]);
}
pub fn print_bits_val<F: FieldExt>(tag: String, x: &[Value<F>]) {
    let y = x.to_vec();
    let asdf2: Value<Vec<F>> = Value::from_iter::<Vec<Value<F>>>(y);
    let asdf3: Value<Vec<u8>> = asdf2.map(|a|
	a.iter().map(|b| { u8::try_from(fe_to_biguint(b)).unwrap() }).collect()
    );
    let asdf4: Value<Vec<u8>> = asdf3.map(|a| {
	let mut b = Vec::new();
	for idx in 0..a.len() / 8 {
	    b.push(a[8 * idx] * 128 + a[8 * idx + 1] * 64 + a[8 * idx + 2] * 32 + a[8 * idx + 3] * 16
		   + a[8 * idx + 4] * 8 + a[8 * idx + 5] * 4 + a[8 * idx + 6] * 2 + a[8 * idx + 7]);
	}
	b
    });
    let asdf5: Value<String> = asdf4.map(|a| encode(a));
    println!("{:?} {:?}", tag, asdf5);
}


#[derive(Clone, Debug)]
pub struct KeccakChip<F: FieldExt> {
    pub values: Vec<Column<Advice>>,
    pub q_xor: Vec<Selector>,
    pub q_xorandn: Vec<Selector>,
    pub constants: Vec<Column<Fixed>>,
    context_id: Rc<String>,
    rate: usize,
    // delimited_suffix: u8,
    output_bit_len: usize,
    _marker: PhantomData<F>,
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
        let values = (0..num_advice)
            .map(|_| {
                let a = meta.advice_column();
                meta.enable_equality(a);
                a
            })
            .collect_vec();
        let q_xor = (0..num_advice).map(|_| meta.selector()).collect_vec();
        let q_xorandn = (0..num_advice).map(|_| meta.selector()).collect_vec();
        let constants = (0..num_fixed)
            .map(|_| {
                let f = meta.fixed_column();
                meta.enable_equality(f);
                f
            })
            .collect_vec();
        let context_id = Rc::new(context_id);

        for i in 0..num_advice {
            meta.create_gate("xor gate", |meta| {
                let q = meta.query_selector(q_xor[i]);
                let a = meta.query_advice(values[i], Rotation::cur());
                let b = meta.query_advice(values[i], Rotation::next());
                let c = meta.query_advice(values[i], Rotation(2));
                vec![q * (a.clone() + b.clone() - Expression::Constant(F::from(2)) * a * b - c)]
            });
            meta.create_gate("a ^ (!b & c) gate", |meta| {
                let q = meta.query_selector(q_xorandn[i]);
                let x = meta.query_advice(values[i], Rotation::cur());
                let y = meta.query_advice(values[i], Rotation::next());
                let z = meta.query_advice(values[i], Rotation(2));
                let d = meta.query_advice(values[i], Rotation(3));

                // x + z − yz − 2xz + 2xyz
                vec![
                    q * (x.clone() + z.clone()
                        - y.clone() * z.clone()
                        - Expression::Constant(F::from(2))
                            * (x.clone() * z.clone() - x.clone() * y.clone() * z.clone())
                        - d),
                ]
            });
        }

        Self {
            values,
            q_xor,
            q_xorandn,
            constants,
            context_id,
            rate,
            // delimited_suffix,
            output_bit_len,
            _marker: PhantomData,
        }
    }

    fn load_zero(&self, ctx: &mut Context<'_, F>) -> AssignedValue<F> {
        if let Some(zero) = &ctx.zero_cell {
            zero.clone()
        } else {
            let zero = self.load_const(ctx, F::zero());
            ctx.zero_cell = Some(zero.clone());
            zero
        }
     }   

    pub fn pad_bytes(
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	inputs: &[AssignedValue<F>],
	len: AssignedValue<F>,
	in_min_len: usize,
	in_max_len: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
	assert_eq!(in_max_len, inputs.len());
	let out_len = ((in_max_len + 1 + 135) / 136) * 136;

	// first pad with 0s and a single 1 postfix
	let mut out_vec_pre = Vec::new();
	for idx in 0..in_min_len {
	    out_vec_pre.push(inputs[idx].clone());
	}
	let mut append: Vec<QuantumCell<F>> = (in_min_len..in_max_len).map(|idx| {
	    inputs[idx].value().zip(len.value()).map(|(v, l)| {
		if idx < usize::try_from(fe_to_biguint(l)).unwrap() {
		    *v
		} else if idx == usize::try_from(fe_to_biguint(l)).unwrap() {
		    F::from(1u64)
		} else {
		    F::zero()
		}
	    })
	}).map(|v| Witness(v)).collect();
	let next = Witness(len.value().map(|l| {
	    if in_max_len == usize::try_from(fe_to_biguint(l)).unwrap() {
		F::from(1u64)
	    } else {
		F::zero()
	    }
	}));
	append.push(next);
	for idx in in_max_len + 1..out_len {
	    append.push(Constant(F::zero()));
	}
	let mut new_out_vec_pre = range.gate.assign_region_smart(ctx, append, vec![], vec![], vec![])?;
	out_vec_pre.append(&mut new_out_vec_pre);
	
	// check equality matches up to len
	let mut is_equal_vec = Vec::new();
	for idx in in_min_len..in_max_len {
	    let is_equal = range.is_equal(ctx, &Existing(&inputs[idx]), &Existing(&out_vec_pre[idx]))?;
	    is_equal_vec.push(is_equal);		
	}

	let mut cumulative_inputs = Vec::new();
	let mut cumulative_gates = Vec::new();
	let mut sum = is_equal_vec[0].value().copied();
	cumulative_inputs.push(Existing(&is_equal_vec[0]));
	for idx in (in_min_len + 1)..in_max_len {
	    cumulative_gates.push(3 * (idx - in_min_len) - 3);
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
	    &out_vec_pre[in_min_len..in_max_len + 1].iter().map(|v| Existing(v)).collect(),
	    &Existing(&len_minus_min_assigned)
	)?;
	range.gate.assert_equal(ctx, &Existing(&idx_len_val), &Constant(F::from(1u64)))?;

	// check padding 0s after index `len`
	let mut is_zero_vec = Vec::new();
	for idx in in_min_len..in_max_len + 1 {	    
	    let is_zero = range.is_zero(ctx, &out_vec_pre[idx])?;
	    is_zero_vec.push(is_zero);		
	}
	let mut cumulative_inputs2 = Vec::new();
	let mut cumulative_gates2 = Vec::new();
	let mut sum2 = is_zero_vec[in_max_len - in_min_len].value().copied();
	cumulative_inputs2.push(Existing(&is_zero_vec[in_max_len - in_min_len]));
	for idx in (in_min_len + 1)..in_max_len + 1 {
	    cumulative_gates2.push(3 * (idx - in_min_len) - 3);
	    cumulative_inputs2.push(Constant(F::one()));
	    cumulative_inputs2.push(Existing(&is_zero_vec[in_max_len - idx]));
	    sum2 = sum2 + is_zero_vec[in_max_len - idx].value().copied();
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
	    &(0..in_max_len + 1 - in_min_len).map(|idx| Existing(&vals2[3 * idx])).collect(),
	    &Existing(&max_minus_len_assigned),
	)?;
	range.gate.assert_equal(ctx, &Existing(&is_zero_sum), &Existing(&max_minus_len_assigned))?;
		
	// now add final padding bit: if input has length len bytes, padding is:
	// | byte idx | len - 1 | len | .. | 136 * N - 1 | ...  | 136 * max - 1|
	// | byte     | XX      | 1   |    | 128          | 0... | 128           |
	// if len == 136 * max - 1, then have 129 instead of 1
	let mut out_vec = Vec::new();
	for idx in 0..in_min_len {
	    out_vec.push(out_vec_pre[idx].clone());	
	}
	for idx in in_min_len..out_len {
	    if (idx + 1) % 136 != 0 {
		out_vec.push(out_vec_pre[idx].clone());
	    } else {
		let is_in_pad_range = range.is_less_than(
		    ctx, &Existing(&len), &Constant(F::from((idx + 1) as u64)), log2(out_len)
		)?;
		let out_val = range.gate.assign_region_smart(
		    ctx,
		    vec![Existing(&out_vec_pre[idx]),
			 Existing(&is_in_pad_range),
			 Constant(F::from(128u64)),
			 Witness(out_vec_pre[idx].value()
				 .zip(is_in_pad_range.value())
				 .map(|(v, p)| *v + (*p) * F::from(128)))],
		    vec![0],
		    vec![],
		    vec![]
		)?;
		out_vec.push(out_val[3].clone());
	    }	
	}
	assert_eq!(out_len, out_vec.len());
	Ok(out_vec)
    }
    
    fn load_const(&self, ctx: &mut Context<'_, F>, c: F) -> AssignedValue<F> {
        self.assign_region(ctx, vec![Constant(c)], vec![], vec![], None).unwrap()[0].clone()
    }

    /// returns leftmost `i` where `advice_rows[context_id][i]` is minimum amongst all `i` where `column[i]` is in phase `phase`
    fn min_gate_index_in(&self, ctx: &Context<'_, F>, phase: u8) -> usize {
        let advice_rows = ctx.advice_rows_get(&self.context_id);

        self.values
            .iter()
            .enumerate()
            .filter(|(_, column)| column.column_type().phase() == phase)
            .min_by(|(i, _), (j, _)| advice_rows[*i].cmp(&advice_rows[*j]))
            .map(|(i, _)| i)
            .expect(format!("Should exist advice column in phase {}", phase).as_str())
    }

    pub fn assign_region(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: Vec<QuantumCell<F>>,
        xor_offsets: Vec<isize>,
        xorandn_offsets: Vec<isize>,
        gate_index: Option<usize>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        self.assign_region_in(
            ctx,
            inputs,
            xor_offsets,
            xorandn_offsets,
            gate_index,
            ctx.current_phase(),
        )
    }

    // same as `assign_region` except you can specify the `phase` to assign in
    pub fn assign_region_in(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: Vec<QuantumCell<F>>,
        xor_offsets: Vec<isize>,
        xorandn_offsets: Vec<isize>,
        gate_index: Option<usize>,
        phase: u8,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let gate_index = if let Some(id) = gate_index {
            assert_eq!(phase, self.values[id].column_type().phase());
            id
        } else {
            self.min_gate_index_in(ctx, phase)
        };
        let row_offset = ctx.advice_rows_get(&self.context_id)[gate_index];
        let input_len = inputs.len();

        let mut assignments = Vec::with_capacity(inputs.len());
        for (i, input) in inputs.into_iter().enumerate() {
            let assigned = ctx.assign_cell(
                input,
                self.values[gate_index],
                &self.context_id,
                gate_index,
                row_offset + i,
                phase,
            )?;
            assignments.push(assigned);
        }
        for &i in &xor_offsets {
            self.q_xor[gate_index].enable(&mut ctx.region, ((row_offset as isize) + i) as usize)?;
        }
        for &i in &xorandn_offsets {
            self.q_xorandn[gate_index]
                .enable(&mut ctx.region, ((row_offset as isize) + i) as usize)?;
        }
        ctx.advice_rows_get_mut(&self.context_id)[gate_index] += input_len;

        Ok(assignments)
    }

    pub fn xor(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: &[&AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error> {
        self.xor_any(ctx, &inputs.iter().map(|a| Existing(*a)).collect_vec())
    }

    pub fn xor_any(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: &[QuantumCell<F>],
    ) -> Result<AssignedValue<F>, Error> {
        assert!(inputs.len() > 1);
        let mut acc = inputs[0]
            .value()
            .zip(inputs[1].value())
            .map(|(a, b)| (a.get_lower_32() ^ b.get_lower_32()) as u64);
        let mut output = self
            .assign_region(
                ctx,
                vec![inputs[0].clone(), inputs[1].clone(), Witness(acc.map(F::from))],
                vec![0],
                vec![],
                None,
            )
            .unwrap()[2]
            .clone();
        let gate_index = output.column();
        for idx in 2..inputs.len() {
            acc = acc.zip(inputs[idx].value()).map(|(a, b)| a ^ (b.get_lower_32() as u64));
            output = self
                .assign_region(
                    ctx,
                    vec![inputs[idx].clone(), Witness(acc.map(F::from))],
                    vec![-1],
                    vec![],
                    Some(gate_index),
                )
                .unwrap()[1]
                .clone();
        }
        Ok(output)
    }

    pub fn xor_and_n(
        &self,
        ctx: &mut Context<'_, F>,
        x: &AssignedValue<F>,
        y: &AssignedValue<F>,
        z: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let v = x.value().zip(y.value()).zip(z.value()).map(|((x, y), z)| {
            F::from((x.get_lower_32() ^ (!y.get_lower_32() & z.get_lower_32())) as u64)
        });
        Ok(self
            .assign_region(
                ctx,
                vec![Existing(x), Existing(y), Existing(z), Witness(v)],
                vec![],
                vec![0],
                None,
            )
            .unwrap()
            .last()
            .unwrap()
            .clone())
    }

    pub fn keccak_f1600_round(
        &self,
        ctx: &mut Context<'_, F>,
        state_bits: &[AssignedValue<F>],
        round: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert_eq!(state_bits.len(), 1600);

        let id = |x, y, z| (64 * (x + 5 * y) + z);

        let c = (0..5)
            .map(|x| {
                (0..64)
                    .map(|z| {
                        self.xor(ctx, &(0..5).map(|y| &state_bits[id(x, y, z)]).collect_vec())
                            .unwrap()
                    })
                    .collect_vec()
            })
            .collect_vec();
        let d = (0..5)
            .map(|x| {
                (0..64)
                    .map(|z| {
                        self.xor(ctx, &[&c[(x + 4) % 5][z], &c[(x + 1) % 5][(z + 63) % 64]])
                            .unwrap()
                    })
                    .collect_vec()
            })
            .collect_vec();

        let mut a = (0..5)
            .flat_map(|y| {
                (0..5)
                    .flat_map(|x| {
                        (0..64)
                            .map(|z| self.xor(ctx, &[&state_bits[id(x, y, z)], &d[x][z]]).unwrap())
                            .collect_vec()
                    })
                    .collect_vec()
            })
            .collect_vec();

        // ρ and π
        // (x,y) -> (3y+x, x) is the inverse transformation to (x,y) -> (y, 2x+3y) all mod 5
        // B[x,y] = rol(A'[3y+x,x], r[3y+x][x])
        let b = |x: usize, y: usize, z: usize| {
            let nx: usize = (3 * y + x) % 5;
            let ny: usize = x;
            let r: usize = ROTATION_OFFSET[nx][ny];
            &a[id(nx, ny, (z + 64 - r) % 64)]
        };

        // χ
        a = (0..5)
            .flat_map(|y| {
                (0..5)
                    .flat_map(|x| {
                        (0..64)
                            .map(|z| {
                                self.xor_and_n(
                                    ctx,
                                    b(x, y, z),
                                    b((x + 1) % 5, y, z),
                                    b((x + 2) % 5, y, z),
                                )
                                .unwrap()
                            })
                            .collect_vec()
                    })
                    .collect_vec()
            })
            .collect_vec();

        for z in 0..64 {
            a[id(0, 0, z)] = self
                .xor_any(ctx, &[Existing(&a[id(0, 0, z)]), Constant(F::from((RC[round] >> z) & 1))])
                .unwrap();
        }

        Ok(a)
    }

    /// returns lanes and updates row_offset to new offset
    pub fn keccak_f1600(
        &self,
        ctx: &mut Context<'_, F>,
        mut state_bits: Vec<AssignedValue<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        for round in 0..24 {
            state_bits = self.keccak_f1600_round(ctx, &state_bits, round).unwrap();
        }
        Ok(state_bits)
    }

    pub fn keccak_fully_padded(
        &self,
        ctx: &mut Context<'_, F>,
        input_bits: &[AssignedValue<F>],
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert!(input_bits.len() % self.rate == 0);
        // === Absorb all the inputs blocks ===
        let mut state_bits: Option<Vec<AssignedValue<F>>> = None;
        let mut input_offset = 0;
        while input_offset < input_bits.len() {
            let block_size = std::cmp::min(input_bits.len() - input_offset, self.rate);
            state_bits = if let Some(mut state_bits) = state_bits {
                for i in 0..block_size {
                    state_bits[i] =
                        self.xor(ctx, &[&state_bits[i], &input_bits[i + input_offset]]).unwrap();
                }
                Some(state_bits)
            } else {
                Some(
                    [
                        &input_bits[0..block_size],
                        &(block_size..1600).map(|_| self.load_zero(ctx)).collect_vec(),
                    ]
                    .concat(),
                )
            };
            input_offset = input_offset + block_size;
            if block_size == self.rate {
                state_bits = Some(self.keccak_f1600(ctx, state_bits.unwrap()).unwrap());
            }
        }

        // === Squeeze phase ===
        let mut output = Vec::with_capacity(self.output_bit_len);
        let mut state_bits = state_bits.unwrap();
        while output.len() < self.output_bit_len {
            let block_size = std::cmp::min(self.output_bit_len - output.len(), self.rate);
            output.extend(state_bits[..block_size].iter().map(|a| a.clone()));
            if output.len() < self.output_bit_len {
                state_bits = self.keccak_f1600(ctx, state_bits).unwrap();
            }
        }

        Ok(output)
    }

    pub fn keccak(
        &self,
        ctx: &mut Context<'_, F>,
        mut input_bits: Vec<AssignedValue<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        // === Padding ===
        input_bits.push(self.load_const(ctx, F::one()));
        while input_bits.len() % self.rate != self.rate - 1 {
            input_bits.push(self.load_const(ctx, F::zero()));
        }
        input_bits.push(self.load_const(ctx, F::one()));

        self.keccak_fully_padded(ctx, &input_bits)
    }

    pub fn keccak_bytes_var_len(
	&self,
	ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
	input: &[AssignedValue<F>],
	len: AssignedValue<F>,
	min_len: usize,
	max_len: usize
    ) -> Result<Vec<AssignedValue<F>>, Error> {
	let padded_bytes = KeccakChip::pad_bytes(ctx, range, &input, len.clone(), 479, 556)?;
        let mut padded_bits = Vec::with_capacity(8 * padded_bytes.len());
        for byte in padded_bytes.iter() {
            let mut bits = range.num_to_bits(ctx, byte, 8)?;
            padded_bits.push(bits[0].clone());
	    padded_bits.push(bits[1].clone());
	    padded_bits.push(bits[2].clone());
	    padded_bits.push(bits[3].clone());
            padded_bits.push(bits[4].clone());
	    padded_bits.push(bits[5].clone());
	    padded_bits.push(bits[6].clone());
	    padded_bits.push(bits[7].clone());	    
        }
        let hash_bits = self.keccak_fully_padded_var_len(
	    ctx, range, &padded_bits[..], len, min_len, max_len
	)?;
	Ok(hash_bits)
    }

    pub fn keccak_fully_padded_var_len(
        &self,
        ctx: &mut Context<'_, F>,
	range: &RangeConfig<F>,
        input_bits: &[AssignedValue<F>],
	len: AssignedValue<F>,
	min_len: usize,
	max_len: usize
    ) -> Result<Vec<AssignedValue<F>>, Error> {
	assert_eq!(input_bits.len() % self.rate, 0);
	let min_rounds = (min_len + 1 + 135) / 136;
	let max_rounds = (max_len + 1 + 135) / 136;

	let mut squeezes = Vec::new();
        let mut state_bits: Option<Vec<AssignedValue<F>>> = None;
        let mut input_offset = 0;
	let mut idx = 0;
        while input_offset < input_bits.len() {
            let block_size = std::cmp::min(input_bits.len() - input_offset, self.rate);
            state_bits = if let Some(mut state_bits) = state_bits {
                for i in 0..block_size {
                    state_bits[i] =
                        self.xor(ctx, &[&state_bits[i], &input_bits[i + input_offset]]).unwrap();
                }
                Some(state_bits)
            } else {
                Some(
                    [
                        &input_bits[0..block_size],
                        &(block_size..1600).map(|_| self.load_zero(ctx)).collect_vec(),
                    ]
                    .concat(),
                )
            };
            input_offset = input_offset + block_size;
            if block_size == self.rate {
                state_bits = Some(self.keccak_f1600(ctx, state_bits.unwrap()).unwrap());
            }

	    if (idx >= min_rounds - 1 && idx < max_rounds) {
		let mut state_bits_out = state_bits.clone().unwrap();
		let mut output: Vec<AssignedValue<F>> = state_bits_out[..self.output_bit_len].iter().map(|a| a.clone()).collect();
		squeezes.push(output);
	    }
	    idx = idx + 1;
        }

	let mut out = squeezes[0].clone();
	let mut is_valid = range.is_less_than(
	    ctx, &Existing(&len), &Constant(F::from((136 * min_rounds) as u64)), log2(136 * max_rounds)
	)?;
	for round_idx in min_rounds..max_rounds {
	    for idx in 0..self.output_bit_len {
		out[idx] = range.gate.select(
		    ctx,
		    &Existing(&out[idx]),
		    &Existing(&squeezes[round_idx - min_rounds + 1][idx]),
		    &Existing(&is_valid)
		)?;
	    }
	    is_valid = range.is_less_than(
		ctx, &Existing(&len), &Constant(F::from((136 * (round_idx + 1)) as u64)), log2(136 * max_rounds)
	    )?;
	}

        Ok(out)
    }        
}

#[derive(Serialize, Deserialize)]
pub struct KeccakCircuitParams {
    pub degree: u32,
    pub num_advice: usize,
    pub num_fixed: usize,
}

#[cfg(test)]
pub(crate) mod tests;

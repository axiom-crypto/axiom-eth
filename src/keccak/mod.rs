use crate::rlp::rlc::log2;
use halo2_base::{
    gates::{range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{fe_to_biguint, value_to_option},
    AssignedValue, Context,
    QuantumCell::{self, Constant, Existing, Witness},
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, TableColumn},
    poly::Rotation,
};
use hex::encode;
use itertools::Itertools;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, rc::Rc};

pub mod merkle_root;

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
    let asdf3: Value<Vec<u8>> =
        asdf2.map(|a| a.iter().map(|b| u8::try_from(fe_to_biguint(b)).unwrap()).collect());
    println!("{:?} {:?}", tag, asdf3.map(|a| encode(a)));
}

pub fn print_bytes_raw<F: FieldExt>(tag: String, x: &[AssignedValue<F>]) {
    let asdf: Vec<Value<F>> = x.iter().map(|a| a.value().copied()).collect();
    let asdf2: Value<Vec<F>> = Value::from_iter::<Vec<Value<F>>>(asdf);
    let asdf3: Value<Vec<u8>> =
        asdf2.map(|a| a.iter().map(|b| u8::try_from(fe_to_biguint(b)).unwrap()).collect());
    println!("{:?} {:?}", tag, asdf3);
}

pub fn print_bits<F: FieldExt>(tag: String, x: &[AssignedValue<F>]) {
    let asdf: Vec<Value<F>> = x.iter().map(|a| a.value().copied()).collect();
    print_bits_val(tag, &asdf[..]);
}
pub fn print_bits_val<F: FieldExt>(tag: String, x: &[Value<F>]) {
    let y = x.to_vec();
    let asdf2: Value<Vec<F>> = Value::from_iter::<Vec<Value<F>>>(y);
    let asdf3: Value<Vec<u8>> =
        asdf2.map(|a| a.iter().map(|b| u8::try_from(fe_to_biguint(b)).unwrap()).collect());
    let asdf4: Value<Vec<u8>> = asdf3.map(|a| {
        let mut b = Vec::new();
        for idx in 0..a.len() / 8 {
            b.push(
                a[8 * idx] * 128
                    + a[8 * idx + 1] * 64
                    + a[8 * idx + 2] * 32
                    + a[8 * idx + 3] * 16
                    + a[8 * idx + 4] * 8
                    + a[8 * idx + 5] * 4
                    + a[8 * idx + 6] * 2
                    + a[8 * idx + 7],
            );
        }
        b
    });
    let asdf5: Value<String> = asdf4.map(|a| encode(a));
    println!("{:?} {:?}", tag, asdf5);
}

// we fix limbs to be nibbles
pub const LOOKUP_BITS: usize = 4;
const LIMBS_PER_LANE: usize = 16; // 64 / LOOKUP_BITS

#[derive(Clone, Debug)]
pub struct RotationChip<F: FieldExt> {
    pub value: Column<Advice>,
    pub q_is_bit: Selector,
    pub q_decompose: Selector,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> RotationChip<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let value = meta.advice_column();
        meta.enable_equality(value);
        let config = Self {
            value,
            q_is_bit: meta.selector(),
            q_decompose: meta.selector(),
            _marker: PhantomData,
        };
        meta.create_gate("is bit", |meta| {
            let q = meta.query_selector(config.q_is_bit);
            let a = meta.query_advice(config.value, Rotation::cur());
            vec![q * (a.clone() * a.clone() - a)]
        });
        meta.create_gate("decompose", |meta| {
            let q = meta.query_selector(config.q_decompose);
            let a = (0..LOOKUP_BITS)
                .map(|i| meta.query_advice(config.value, Rotation(i as i32)))
                .collect_vec();
            let out = meta.query_advice(config.value, Rotation(LOOKUP_BITS as i32));
            vec![
                q * (a.iter().enumerate().fold(Expression::Constant(F::zero()), |acc, (i, b)| {
                    acc + Expression::Constant(F::from(1u64 << i)) * b.clone()
                }) - out),
            ]
        });
        config
    }
}

#[derive(Clone, Debug)]
pub struct KeccakChip<F: FieldExt> {
    pub rotation: Vec<RotationChip<F>>,
    pub xor_values: Vec<Column<Advice>>,
    pub xorandn_values: Vec<Column<Advice>>,
    pub constants: Vec<Column<Fixed>>,
    pub lookups: [TableColumn; 5], // a, b, c, a ^ b, a ^ (!b & c)
    context_id: Rc<String>,
    xor_id: Rc<String>,
    xorandn_id: Rc<String>,
    rate_in_limbs: usize,
    // delimited_suffix: u8,
    output_limb_len: usize,
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
        num_xor: usize,
        num_xorandn: usize,
        num_fixed: usize,
    ) -> Self {
        assert_eq!(rate % LOOKUP_BITS, 0);
        let rotation = (0..num_advice).map(|_| RotationChip::configure(meta)).collect_vec();
        let xor_values = (0..3 * num_xor)
            .map(|_| {
                let a = meta.advice_column();
                meta.enable_equality(a);
                a
            })
            .collect_vec();
        let xorandn_values = (0..4 * num_xorandn)
            .map(|_| {
                let a = meta.advice_column();
                meta.enable_equality(a);
                a
            })
            .collect_vec();
        let constants = (0..num_fixed)
            .map(|_| {
                let f = meta.fixed_column();
                meta.enable_equality(f);
                f
            })
            .collect_vec();
        let lookups: [TableColumn; 5] =
            (0..5).map(|_| meta.lookup_table_column()).collect_vec().try_into().unwrap();

        for i in 0..num_xor {
            meta.lookup("a ^ b = c", |meta| {
                let a = meta.query_advice(xor_values[3 * i], Rotation::cur());
                let b = meta.query_advice(xor_values[3 * i + 1], Rotation::cur());
                let c = meta.query_advice(xor_values[3 * i + 2], Rotation::cur());
                vec![(a, lookups[0]), (b, lookups[1]), (c, lookups[3])]
            });
        }
        for i in 0..num_xorandn {
            meta.lookup("a ^ (!b & c) = d", |meta| {
                let a = meta.query_advice(xorandn_values[4 * i], Rotation::cur());
                let b = meta.query_advice(xorandn_values[4 * i + 1], Rotation::cur());
                let c = meta.query_advice(xorandn_values[4 * i + 2], Rotation::cur());
                let d = meta.query_advice(xorandn_values[4 * i + 3], Rotation::cur());
                vec![(a, lookups[0]), (b, lookups[1]), (c, lookups[2]), (d, lookups[4])]
            });
        }

        Self {
            rotation,
            xor_values,
            xorandn_values,
            constants,
            lookups,
            context_id: Rc::new(context_id.clone()),
            xor_id: Rc::new(format!("{}_xor", context_id)),
            xorandn_id: Rc::new(format!("{}_xorandn", context_id)),
            rate_in_limbs: rate / LOOKUP_BITS,
            // delimited_suffix,
            output_limb_len: output_bit_len / LOOKUP_BITS,
            _marker: PhantomData,
        }
    }

    pub fn load_lookup_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "xor and xorandn table",
            |mut table| {
                let mut offset = 0;
                for a in 0..1 << LOOKUP_BITS {
                    for b in 0..1 << LOOKUP_BITS {
                        for c in 0..1 << LOOKUP_BITS {
                            table.assign_cell(
                                || "a",
                                self.lookups[0],
                                offset,
                                || Value::known(F::from(a)),
                            )?;
                            table.assign_cell(
                                || "b",
                                self.lookups[1],
                                offset,
                                || Value::known(F::from(b)),
                            )?;
                            table.assign_cell(
                                || "c",
                                self.lookups[2],
                                offset,
                                || Value::known(F::from(c)),
                            )?;
                            table.assign_cell(
                                || "a ^ b",
                                self.lookups[3],
                                offset,
                                || Value::known(F::from(a ^ b)),
                            )?;
                            table.assign_cell(
                                || "a ^ (!b & c)",
                                self.lookups[4],
                                offset,
                                || Value::known(F::from(a ^ (!b & c))),
                            )?;
                            offset += 1;
                        }
                    }
                }
                Ok(())
            },
        )
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
        let mut out_vec_pre = Vec::with_capacity(in_max_len);
        out_vec_pre.extend_from_slice(&inputs[..in_min_len]);
        let mut append: Vec<QuantumCell<F>> = (in_min_len..in_max_len)
            .map(|idx| {
                inputs[idx].value().zip(len.value()).map(|(v, l)| {
                    if idx < l.get_lower_32() as usize {
                        *v
                    } else if idx == l.get_lower_32() as usize {
                        F::from(1u64)
                    } else {
                        F::zero()
                    }
                })
            })
            .map(|v| Witness(v))
            .collect();
        let next = Witness(len.value().map(|l| {
            if in_max_len == l.get_lower_32() as usize {
                F::from(1u64)
            } else {
                F::zero()
            }
        }));
        append.push(next);
        append.extend((in_max_len + 1..out_len).map(|_| Constant(F::zero())).into_iter());
        let mut new_out_vec_pre =
            range.gate.assign_region_smart(ctx, append, vec![], vec![], vec![])?;
        out_vec_pre.append(&mut new_out_vec_pre);

        // TODO: What if in_min_len = in_max_len?
        // check equality matches up to len
        let mut is_equal_vec = Vec::new();
        for idx in in_min_len..in_max_len {
            let is_equal =
                range.is_equal(ctx, &Existing(&inputs[idx]), &Existing(&out_vec_pre[idx]))?;
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
            ctx,
            cumulative_inputs,
            cumulative_gates,
            vec![],
            vec![],
        )?;
        let len_minus_min_val = len.value().copied() - Value::known(F::from(in_min_len as u64));
        let val = range.gate.assign_region_smart(
            ctx,
            vec![
                Witness(len_minus_min_val),
                Constant(F::one()),
                Constant(F::from(in_min_len as u64)),
                Existing(&len),
            ],
            vec![0],
            vec![],
            vec![],
        )?;
        let len_minus_min_assigned = val[0].clone();
        let is_equal_sum = range.gate.select_from_idx(
            ctx,
            &(0..in_max_len - in_min_len).map(|idx| Existing(&vals[3 * idx])).collect(),
            &Existing(&len_minus_min_assigned),
        )?;
        // println!("TEST3 {:?} {:?}", is_equal_sum.value(), len_minus_min_assigned.value());
        range.gate.assert_equal(
            ctx,
            &Existing(&is_equal_sum),
            &Existing(&len_minus_min_assigned),
        )?;

        // check padding val at index `len`
        let idx_len_val = range.gate.select_from_idx(
            ctx,
            &out_vec_pre[in_min_len..in_max_len + 1].iter().map(|v| Existing(v)).collect(),
            &Existing(&len_minus_min_assigned),
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
            ctx,
            cumulative_inputs2,
            cumulative_gates2,
            vec![],
            vec![],
        )?;
        let max_minus_len_val = Value::known(F::from(in_max_len as u64)) - len.value().copied();
        let val2 = range.gate.assign_region_smart(
            ctx,
            vec![
                Witness(max_minus_len_val),
                Constant(F::one()),
                Existing(&len),
                Constant(F::from(in_max_len as u64)),
            ],
            vec![0],
            vec![],
            vec![],
        )?;
        let max_minus_len_assigned = val2[0].clone();
        let is_zero_sum = range.gate.select_from_idx(
            ctx,
            &(0..in_max_len + 1 - in_min_len).map(|idx| Existing(&vals2[3 * idx])).collect(),
            &Existing(&max_minus_len_assigned),
        )?;

        // println!("TEST5 {:?} {:?}", is_zero_sum.value(), max_minus_len_assigned.value());
        range.gate.assert_equal(
            ctx,
            &Existing(&is_zero_sum),
            &Existing(&max_minus_len_assigned),
        )?;

        // now add final padding bit: if input has length len bytes, padding is:
        // | byte idx | len - 1 | len | .. | 136 * N - 1 | ...  | 136 * max - 1|
        // | byte     | XX      | 1   |    | 128          | 0... | 128           |
        // if len == 136 * max - 1, then have 129 instead of 1
        let mut out_vec = out_vec_pre;
        assert_eq!(out_vec.len(), out_len);
        for (idx, out) in out_vec.iter_mut().enumerate().skip(in_min_len) {
            if (idx + 1) % 136 == 0 {
                let is_in_pad_range = range.is_less_than_safe(ctx, &len, idx + 1, log2(out_len))?;
                let out_val = range
                    .gate
                    .assign_region_smart(
                        ctx,
                        vec![
                            Existing(out),
                            Existing(&is_in_pad_range),
                            Constant(F::from(128u64)),
                            Witness(
                                out.value()
                                    .zip(is_in_pad_range.value())
                                    .map(|(v, p)| *v + (*p) * F::from(128)),
                            ),
                        ],
                        vec![0],
                        vec![],
                        vec![],
                    )?
                    .into_iter()
                    .nth(3)
                    .unwrap();
                *out = out_val;
            }
        }
        Ok(out_vec)
    }

    fn load_const(&self, ctx: &mut Context<'_, F>, c: F) -> AssignedValue<F> {
        self.assign_region(ctx, vec![Constant(c)], None, vec![], vec![]).unwrap()[0].clone()
    }

    fn min_rot_index_in(&self, ctx: &Context<'_, F>, phase: u8) -> usize {
        let advice_rows = ctx.advice_rows_get(&self.context_id);

        (0..advice_rows.len())
            .filter(|&i| self.rotation[i].value.column_type().phase() == phase)
            .min_by(|i, j| advice_rows[*i].cmp(&advice_rows[*j]))
            .expect(format!("Should exist advice column in phase {}", phase).as_str())
    }

    fn min_xor_index_in(&self, ctx: &Context<'_, F>, phase: u8) -> usize {
        let advice_rows = ctx.advice_rows_get(&self.xor_id);

        (0..advice_rows.len())
            .filter(|&i| {
                (3 * i..3 * i + 3).all(|j| self.xor_values[j].column_type().phase() == phase)
            })
            .min_by(|i, j| advice_rows[*i].cmp(&advice_rows[*j]))
            .expect(format!("Should exist advice column in phase {}", phase).as_str())
    }

    fn min_xorandn_index_in(&self, ctx: &Context<'_, F>, phase: u8) -> usize {
        let advice_rows = ctx.advice_rows_get(&self.xorandn_id);

        (0..advice_rows.len())
            .filter(|&i| {
                (4 * i..4 * i + 4).all(|j| self.xorandn_values[j].column_type().phase() == phase)
            })
            .min_by(|i, j| advice_rows[*i].cmp(&advice_rows[*j]))
            .expect(format!("Should exist advice column in phase {}", phase).as_str())
    }

    pub fn assign_region(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: Vec<QuantumCell<F>>,
        column_index: Option<usize>,
        is_bit_offsets: Vec<isize>,
        decompose_offsets: Vec<isize>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        self.assign_region_in(
            ctx,
            inputs,
            column_index,
            is_bit_offsets,
            decompose_offsets,
            ctx.current_phase(),
        )
    }

    // same as `assign_region` except you can specify the `phase` to assign in
    pub fn assign_region_in(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: Vec<QuantumCell<F>>, // there are no gates!
        column_index: Option<usize>,
        is_bit_offsets: Vec<isize>,
        decompose_offsets: Vec<isize>,
        phase: u8,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let gate_index =
            if let Some(id) = column_index { id } else { self.min_rot_index_in(ctx, phase) };
        let row_offset = ctx.advice_rows_get(&self.context_id)[gate_index];

        let mut assignments = Vec::with_capacity(inputs.len());
        for (i, input) in inputs.iter().enumerate() {
            let assigned = ctx.assign_cell(
                input.clone(),
                self.rotation[gate_index].value,
                &self.context_id,
                gate_index,
                row_offset + i,
                phase,
            )?;
            assignments.push(assigned);
        }
        for &i in &is_bit_offsets {
            self.rotation[gate_index]
                .q_is_bit
                .enable(&mut ctx.region, (row_offset as isize + i) as usize)?;
        }
        for &i in &decompose_offsets {
            self.rotation[gate_index]
                .q_decompose
                .enable(&mut ctx.region, (row_offset as isize + i) as usize)?;
        }

        ctx.advice_rows_get_mut(&self.context_id)[gate_index] += inputs.len();

        Ok(assignments)
    }

    // maps 16 * x + y to (x, y)
    pub fn byte_to_hex(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        a: &AssignedValue<F>,
    ) -> Result<(AssignedValue<F>, AssignedValue<F>), Error> {
        let assigned = range.gate.assign_region_smart(
            ctx,
            vec![
                Witness(a.value().map(|aa| {
                    F::from(u64::try_from(fe_to_biguint(aa) % BigUint::from(16u64)).unwrap())
                })),
                Constant(F::from(16)),
                Witness(a.value().map(|aa| {
                    F::from(u64::try_from(fe_to_biguint(aa) / BigUint::from(16u64)).unwrap())
                })),
                Existing(a),
            ],
            vec![0],
            vec![],
            vec![],
        )?;
        self.xor(ctx, &[&assigned[0], &assigned[2]])?;
        Ok((assigned[2].clone(), assigned[0].clone()))
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
        #[cfg(feature = "display")]
        {
            let count = ctx.op_count.entry("xor".to_string()).or_insert(0);
            *count += inputs.len() - 1;
        }
        let phase = ctx.current_phase();
        let id = self.min_xor_index_in(ctx, phase);
        let row_offset = ctx.advice_rows_get(&self.xor_id)[id];

        let mut acc = inputs[0]
            .value()
            .zip(inputs[1].value())
            .map(|(a, b)| (a.get_lower_32() ^ b.get_lower_32()) as u64);

        ctx.assign_cell(
            inputs[0].clone(),
            self.xor_values[3 * id],
            &self.xor_id,
            3 * id,
            row_offset,
            phase,
        )?;
        ctx.assign_cell(
            inputs[1].clone(),
            self.xor_values[3 * id + 1],
            &self.xor_id,
            3 * id + 1,
            row_offset,
            phase,
        )?;
        let mut output = ctx.assign_cell(
            Witness(acc.map(F::from)),
            self.xor_values[3 * id + 2],
            &self.xor_id,
            3 * id + 2,
            row_offset,
            phase,
        )?;

        for idx in 2..inputs.len() {
            acc = acc.zip(inputs[idx].value()).map(|(a, b)| a ^ (b.get_lower_32() as u64));
            ctx.assign_cell(
                Existing(&output),
                self.xor_values[3 * id],
                &self.xor_id,
                3 * id,
                row_offset + idx - 1,
                phase,
            )?;
            ctx.assign_cell(
                inputs[idx].clone(),
                self.xor_values[3 * id + 1],
                &self.xor_id,
                3 * id + 1,
                row_offset + idx - 1,
                phase,
            )?;
            output = ctx.assign_cell(
                Witness(acc.map(F::from)),
                self.xor_values[3 * id + 2],
                &self.xor_id,
                3 * id + 2,
                row_offset + idx - 1,
                phase,
            )?;
        }
        ctx.advice_rows_get_mut(&self.xor_id)[id] += inputs.len() - 1;
        Ok(output)
    }

    pub fn xor_and_n(
        &self,
        ctx: &mut Context<'_, F>,
        x: &AssignedValue<F>,
        y: &AssignedValue<F>,
        z: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        #[cfg(feature = "display")]
        {
            let count = ctx.op_count.entry("xor_and_n".to_string()).or_insert(0);
            *count += 1;
        }
        let v = x.value().zip(y.value()).zip(z.value()).map(|((x, y), z)| {
            F::from((x.get_lower_32() ^ (!y.get_lower_32() & z.get_lower_32())) as u64)
        });
        let phase = ctx.current_phase();
        let id = self.min_xorandn_index_in(ctx, phase);
        let row_offset = ctx.advice_rows_get(&self.xorandn_id)[id];

        ctx.assign_cell(
            Existing(x),
            self.xorandn_values[4 * id],
            &self.xorandn_id,
            4 * id,
            row_offset,
            phase,
        )?;
        ctx.assign_cell(
            Existing(y),
            self.xorandn_values[4 * id + 1],
            &self.xorandn_id,
            4 * id + 1,
            row_offset,
            phase,
        )?;
        ctx.assign_cell(
            Existing(z),
            self.xorandn_values[4 * id + 2],
            &self.xorandn_id,
            4 * id + 2,
            row_offset,
            phase,
        )?;
        let output = ctx.assign_cell(
            Witness(v),
            self.xorandn_values[4 * id + 3],
            &self.xorandn_id,
            4 * id + 3,
            row_offset,
            phase,
        )?;
        ctx.advice_rows_get_mut(&self.xorandn_id)[id] += 1;
        Ok(output)
    }

    pub fn num_to_bits(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let mut bits = (0..LOOKUP_BITS)
            .map(|i| a.value().map(|a| F::from((a.get_lower_32() as u64 >> i) & 1)))
            .map(|v| Witness(v))
            .collect_vec();
        bits.push(Existing(a));
        let mut output = self.assign_region(
            ctx,
            bits,
            None,
            (0..LOOKUP_BITS).map(|i| i as isize).collect_vec(),
            vec![0],
        )?;
        output.pop();
        Ok(output)
    }

    pub fn bits_to_num(
        &self,
        ctx: &mut Context<'_, F>,
        bits: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error> {
        assert_eq!(bits.len(), LOOKUP_BITS);
        let v = (0..LOOKUP_BITS).fold(Value::known(F::zero()), |acc, i| {
            acc + bits[i].value().map(|x| F::from(1u64 << i) * x)
        });
        let mut assignments = self
            .assign_region(
                ctx,
                bits.iter().map(|a| Existing(a)).chain([Witness(v)]).collect_vec(),
                None,
                vec![],
                vec![0],
            )
            .unwrap();
        Ok(assignments.pop().unwrap())
    }

    pub fn rol64(
        &self,
        ctx: &mut Context<'_, F>,
        a: &[AssignedValue<F>],
        n: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert_eq!(a.len(), LIMBS_PER_LANE);
        let n = n % 64;
        if n % LOOKUP_BITS == 0 {
            let n = n / LOOKUP_BITS;
            return Ok((0..LIMBS_PER_LANE)
                .map(|i| a[(i + LIMBS_PER_LANE - n) % LIMBS_PER_LANE].clone())
                .collect_vec());
        }
        let mut bits = Vec::with_capacity(64);
        for limb in a.iter() {
            bits.append(&mut self.num_to_bits(ctx, limb).unwrap());
        }
        let mut output = Vec::with_capacity(LIMBS_PER_LANE);
        for i in (0..64).step_by(LOOKUP_BITS) {
            output.push(
                self.bits_to_num(
                    ctx,
                    &(i..i + LOOKUP_BITS).map(|z| bits[(z + 64 - n) % 64].clone()).collect_vec(),
                )
                .unwrap(),
            );
        }
        Ok(output)
    }

    pub fn keccak_f1600_round(
        &self,
        ctx: &mut Context<'_, F>,
        state: &[AssignedValue<F>],
        round: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert_eq!(state.len(), 25 * LIMBS_PER_LANE);

        let id = |x: usize, y: usize, z: usize| (LIMBS_PER_LANE * (x + 5 * y) + z);

        /*
        for x in 0..5 {
            for y in 0..5 {
                println!(
                    "{:?}",
                    halo2_base::utils::compose(
                        (0..16)
                            .map(|z| halo2_base::utils::fe_to_biguint(
                                halo2_base::utils::value_to_option(state[id(x, y, z)].value())
                                    .unwrap()
                            ))
                            .collect_vec(),
                        4
                    )
                );
            }
        }
        println!("");*/
        let c = (0..5)
            .map(|x| {
                (0..LIMBS_PER_LANE)
                    .map(|z| {
                        self.xor(ctx, &(0..5).map(|y| &state[id(x, y, z)]).collect_vec()).unwrap()
                    })
                    .collect_vec()
            })
            .collect_vec();

        let d = (0..5)
            .map(|x| {
                let tmp = self.rol64(ctx, &c[(x + 1) % 5], 1).unwrap();
                (0..LIMBS_PER_LANE)
                    .map(|z| self.xor(ctx, &[&c[(x + 4) % 5][z], &tmp[z]]).unwrap())
                    .collect_vec()
            })
            .collect_vec();

        let mut a = (0..5)
            .flat_map(|y| {
                (0..5)
                    .flat_map(|x| {
                        (0..LIMBS_PER_LANE)
                            .map(|z| self.xor(ctx, &[&state[id(x, y, z)], &d[x][z]]).unwrap())
                            .collect_vec()
                    })
                    .collect_vec()
            })
            .collect_vec();

        // ρ and π
        // (x,y) -> (3y+x, x) is the inverse transformation to (x,y) -> (y, 2x+3y) all mod 5
        // B[x,y] = rol(A'[3y+x,x], r[3y+x][x])
        let b = (0..5)
            .map(|x| {
                (0..5)
                    .map(|y| {
                        let nx: usize = (3 * y + x) % 5;
                        let ny: usize = x;
                        self.rol64(
                            ctx,
                            &a[LIMBS_PER_LANE * (nx + 5 * ny)..LIMBS_PER_LANE * (nx + 5 * ny + 1)],
                            ROTATION_OFFSET[nx][ny],
                        )
                        .unwrap()
                    })
                    .collect_vec()
            })
            .collect_vec();

        // χ
        a = (0..5)
            .flat_map(|y| {
                (0..5)
                    .flat_map(|x| {
                        (0..LIMBS_PER_LANE)
                            .map(|z| {
                                self.xor_and_n(
                                    ctx,
                                    &b[x][y][z],
                                    &b[(x + 1) % 5][y][z],
                                    &b[(x + 2) % 5][y][z],
                                )
                                .unwrap()
                            })
                            .collect_vec()
                    })
                    .collect_vec()
            })
            .collect_vec();

        for z in 0..LIMBS_PER_LANE {
            a[id(0, 0, z)] = self
                .xor_any(
                    ctx,
                    &[
                        Existing(&a[id(0, 0, z)]),
                        Constant(F::from(
                            (RC[round] >> (LOOKUP_BITS * z)) & ((1 << LOOKUP_BITS) - 1),
                        )),
                    ],
                )
                .unwrap();
        }

        Ok(a)
    }

    /// returns lanes and updates row_offset to new offset
    pub fn keccak_f1600(
        &self,
        ctx: &mut Context<'_, F>,
        mut state: Vec<AssignedValue<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        for round in 0..24 {
            state = self.keccak_f1600_round(ctx, &state, round).unwrap();
        }
        Ok(state)
    }

    pub fn keccak_fully_padded(
        &self,
        ctx: &mut Context<'_, F>,
        input_limbs: &[AssignedValue<F>],
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert_eq!(input_limbs.len() % self.rate_in_limbs, 0);
        // === Absorb all the inputs blocks ===
        let mut state_bits: Option<Vec<AssignedValue<F>>> = None;
        let mut input_offset = 0;
        while input_offset < input_limbs.len() {
            let block_size = std::cmp::min(input_limbs.len() - input_offset, self.rate_in_limbs);
            state_bits = if let Some(mut state_bits) = state_bits {
                for i in 0..block_size {
                    state_bits[i] =
                        self.xor(ctx, &[&state_bits[i], &input_limbs[i + input_offset]]).unwrap();
                }
                Some(state_bits)
            } else {
                Some(
                    [
                        &input_limbs[0..block_size],
                        &(block_size..25 * LIMBS_PER_LANE)
                            .map(|_| self.load_zero(ctx))
                            .collect_vec(),
                    ]
                    .concat(),
                )
            };
            input_offset = input_offset + block_size;
            if block_size == self.rate_in_limbs {
                state_bits = Some(self.keccak_f1600(ctx, state_bits.unwrap()).unwrap());
            }
        }

        // === Squeeze phase ===
        let mut output = Vec::with_capacity(self.output_limb_len);
        let mut state_bits = state_bits.unwrap();
        while output.len() < self.output_limb_len {
            let block_size = std::cmp::min(self.output_limb_len - output.len(), self.rate_in_limbs);
            output.extend(state_bits[..block_size].iter().map(|a| a.clone()));
            if output.len() < self.output_limb_len {
                state_bits = self.keccak_f1600(ctx, state_bits).unwrap();
            }
        }

        Ok(output)
    }

    pub fn keccak(
        &self,
        ctx: &mut Context<'_, F>,
        mut input_limbs: Vec<AssignedValue<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        // === Padding ===
        input_limbs.push(self.load_const(ctx, F::one()));
        while input_limbs.len() % self.rate_in_limbs != self.rate_in_limbs - 1 {
            input_limbs.push(self.load_const(ctx, F::zero()));
        }
        input_limbs.push(self.load_const(ctx, F::from(1 << (LOOKUP_BITS - 1))));

        self.keccak_fully_padded(ctx, &input_limbs)
    }

    pub fn keccak_bytes_fixed_len(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        input: &[AssignedValue<F>],
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let mut nibbles = Vec::with_capacity(2 * input.len());
        for byte in input.iter() {
            let (hex1, hex2) = self.byte_to_hex(ctx, range, byte)?;
            nibbles.extend([hex2, hex1].into_iter());
        }
        let hash_nibbles = self.keccak(ctx, nibbles)?;
        let mut hash_bytes = Vec::with_capacity(32);
        for idx in (0..64).step_by(2) {
            let (_, _, byte) = range.gate.inner_product(
                ctx,
                &hash_nibbles[idx..idx + 2].iter().map(|a| Existing(a)).collect(),
                &[1, 16].map(|a| Constant(F::from(a))).into_iter().collect(),
            )?;
            hash_bytes.push(byte);
        }
        Ok(hash_bytes)
    }

    /// Return (output in bytes, output in hexes)
    pub fn keccak_bytes_var_len(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        input: &[AssignedValue<F>],
        len: AssignedValue<F>,
        min_len: usize,
        max_len: usize,
    ) -> Result<(Vec<AssignedValue<F>>, Vec<AssignedValue<F>>), Error> {
        assert_eq!(input.len(), max_len);
        // TODO: something wrong here when `len` is close to `max_len` or something
        let padded_bytes =
            KeccakChip::pad_bytes(ctx, range, &input, len.clone(), min_len, max_len)?;
        let mut padded_hexs = Vec::with_capacity(8 * padded_bytes.len());
        // byte string is big endian, but keccak internals are in little endian
        for byte in padded_bytes.iter() {
            let (hex1, hex2) = self.byte_to_hex(ctx, range, &byte)?;
            // byte to hex is little endian
            padded_hexs.push(hex2);
            padded_hexs.push(hex1);
        }
        self.keccak_fully_padded_var_len(ctx, range, &padded_hexs[..], len, min_len, max_len)
    }

    /// Return (output in bytes, output in hexes)
    pub fn keccak_fully_padded_var_len(
        &self,
        ctx: &mut Context<'_, F>,
        range: &RangeConfig<F>,
        input_hexs: &[AssignedValue<F>],
        len: AssignedValue<F>,
        min_len: usize,
        max_len: usize,
    ) -> Result<(Vec<AssignedValue<F>>, Vec<AssignedValue<F>>), Error> {
        assert_eq!(input_hexs.len() % self.rate_in_limbs, 0);
        let min_rounds = (min_len + 1 + 135) / 136;
        let max_rounds = (max_len + 1 + 135) / 136;

        let mut squeezes = Vec::new();
        let mut state_bits: Option<Vec<AssignedValue<F>>> = None;
        let mut input_offset = 0;
        let mut idx = 0;
        while input_offset < input_hexs.len() {
            let block_size = std::cmp::min(input_hexs.len() - input_offset, self.rate_in_limbs);
            state_bits = if let Some(mut state_bits) = state_bits {
                for i in 0..block_size {
                    state_bits[i] =
                        self.xor(ctx, &[&state_bits[i], &input_hexs[i + input_offset]]).unwrap();
                }
                Some(state_bits)
            } else {
                Some(
                    [
                        &input_hexs[0..block_size],
                        &(block_size..25 * LIMBS_PER_LANE)
                            .map(|_| self.load_zero(ctx))
                            .collect_vec(),
                    ]
                    .concat(),
                )
            };
            input_offset = input_offset + block_size;
            if block_size == self.rate_in_limbs {
                state_bits = Some(self.keccak_f1600(ctx, state_bits.unwrap()).unwrap());
            }

            if idx >= min_rounds - 1 && idx < max_rounds {
                let output: Vec<AssignedValue<F>> = state_bits.as_ref().unwrap()
                    [..self.output_limb_len]
                    .iter()
                    .map(|a| a.clone())
                    .collect();
                squeezes.push(output);
            }
            idx = idx + 1;
        }

        let mut out = squeezes[0].clone();
        // TODO: Remove extra range checks on len
        let mut is_valid =
            range.is_less_than_safe(ctx, &len, 136 * min_rounds, log2(136 * max_rounds))?;
        for round_idx in min_rounds..max_rounds {
            for idx in 0..self.output_limb_len {
                out[idx] = range.gate.select(
                    ctx,
                    &Existing(&out[idx]),
                    &Existing(&squeezes[round_idx - min_rounds + 1][idx]),
                    &Existing(&is_valid),
                )?;
            }
            // TODO: Remove extra range checks on len
            is_valid = range.is_less_than_safe(
                ctx,
                &len,
                136 * (round_idx + 1),
                log2(136 * max_rounds),
            )?;
        }

        let mut hash_bytes = Vec::with_capacity(32);
        for idx in (0..64).step_by(2) {
            let (_, _, byte) = range.gate.inner_product(
                ctx,
                &out[idx..idx + 2].iter().map(|a| Existing(a)).collect(),
                &[1, 16].map(|a| Constant(F::from(a))).into_iter().collect(),
            )?;
            // println!("CONCAT byte: {:?}", byte);
            hash_bytes.push(byte);
        }
        // print_bytes("hash".to_string(), &hash_bytes);

        Ok((hash_bytes, out))
    }

    /// `leaves` is slice of hex arrays
    // format is hex because that is what our keccak format is
    /// returns merkle tree root as a hex array in little endian
    pub fn merkle_tree_root(
        &self,
        ctx: &mut Context<'_, F>,
        leaves: &[&[AssignedValue<F>]],
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let depth = leaves.len().ilog2() as usize;
        if depth == 0 {
            return Ok(leaves[0].iter().cloned().collect());
        }
        assert_eq!(1 << depth, leaves.len());
        let mut hashes = Vec::with_capacity(1 << (depth - 1));
        for i in 0..(1 << (depth - 1)) {
            let hash = self.keccak(ctx, [leaves[2 * i], leaves[2 * i + 1]].concat())?;
            hashes.push(hash);
        }
        for d in (0..depth - 1).rev() {
            for i in 0..(1 << d) {
                hashes[i] = self.keccak(
                    ctx,
                    [hashes[2 * i].as_slice(), hashes[2 * i + 1].as_slice()].concat(),
                )?;
            }
        }
        Ok(hashes[0].clone())
    }
}

#[derive(Serialize, Deserialize)]
pub struct KeccakCircuitParams {
    pub degree: u32,
    pub num_advice: usize,
    pub num_xor: usize,
    pub num_xorandn: usize,
    pub num_fixed: usize,
    pub num_keccak_f: usize,
}

#[cfg(test)]
pub(crate) mod tests;

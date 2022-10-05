use halo2_base::{
    AssignedValue, Context,
    QuantumCell::{self, Constant, Existing, Witness},
};
use halo2_proofs::{
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, rc::Rc};

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
}

#[derive(Serialize, Deserialize)]
pub struct KeccakCircuitParams {
    pub degree: u32,
    pub num_advice: usize,
    pub num_fixed: usize,
}

#[cfg(test)]
pub(crate) mod tests;

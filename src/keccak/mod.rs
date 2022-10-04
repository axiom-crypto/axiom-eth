#![allow(non_snake_case)]
// we implement Keccak without lookups using the custom gates found in https://blog.polygon.technology/zk-white-paper-efficient-zk-proofs-for-keccak/
// keccak python code reference: https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py
use halo2_base::{
    utils::value_to_option,
    AssignedValue, Context,
    QuantumCell::{self, Existing, Witness},
};
use halo2_proofs::{
    circuit::Value,
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
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
pub struct KeccakBitConfig<F: FieldExt> {
    // we will represent each 64-bit word as a single row
    pub values: [Column<Advice>; LANE_LEN],
    pub q_rounds: [Selector; ROUNDS],
    pub context_id: Rc<String>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> KeccakBitConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, context_id: String) -> Self {
        let values: [_; LANE_LEN] = (0..LANE_LEN)
            .map(|_| {
                let a = meta.advice_column();
                meta.enable_equality(a);
                a
            })
            .collect_vec()
            .try_into()
            .unwrap();
        let q_rounds: [_; ROUNDS] =
            (0..ROUNDS).map(|_| meta.selector()).collect_vec().try_into().unwrap();

        let config =
            Self { values, q_rounds, context_id: Rc::new(context_id), _marker: PhantomData };
        for round in 0..24 {
            config.create_gate(meta, round);
        }
        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<F>, round: usize) {
        // We closely follow PolygonZero's paper, except that since our field F is >64 bits, we can use 64-bit packed words instead of 32-bit packed words
        // In these comments, `A` will mean bold A in their paper (so A[x,y] means the 64-bit word in lane (x,y)), `a` will mean non-bold A (so a[x,y,z] means the z-th bit of A[x,y])

        // This gate will constrain one round of keccak-f[1600]
        // The gate will access all cells in a 64 column by 37 row matrix:
        // The inputs A[0..5, 0..5] and outputs A''[0..5, 0..5], A'''[0,0] -- 51 values in total, are all in the first row
        // Each of c[x,0..64] takes up one row for each x
        // Each of a'[x,y,0..64] takes up one row
        // Each of c'[x,0..64] takes up one row
        // a''[0,0,0..64] takes up one row

        // For fast proving speed, it is better to have all gates use the same set of Rotations
        // thus we will put all constraints into a single gate which accesses Rotation(0..37)
        meta.create_gate("one round of keccak-f[1600]", |meta| {
            let q = meta.query_selector(self.q_rounds[round]);

            let A: Vec<Vec<Expression<F>>> = (0..5)
                .map(|x| {
                    (0..5)
                        .map(|y| meta.query_advice(self.values[5 * x + y], Rotation::cur()))
                        .collect_vec()
                })
                .collect_vec();
            // App = A'', Appp = A''', ap = a', cp = c'
            let App: Vec<Vec<Expression<F>>> = (0..5)
                .map(|x| {
                    (0..5)
                        .map(|y| meta.query_advice(self.values[25 + 5 * x + y], Rotation::cur()))
                        .collect_vec()
                })
                .collect_vec();

            let Appp_00 = meta.query_advice(self.values[50], Rotation::cur());

            let c: Vec<Vec<Expression<F>>> = (0..5)
                .map(|x| {
                    self.values
                        .iter()
                        .map(|column| meta.query_advice(column.clone(), Rotation((1 + x) as i32)))
                        .collect_vec()
                })
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
                                        Rotation((6 + 5 * x + y) as i32),
                                    )
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
                        .map(|column| meta.query_advice(column.clone(), Rotation((31 + x) as i32)))
                        .collect_vec()
                })
                .collect_vec();

            let app_00: Vec<Expression<F>> = self
                .values
                .iter()
                .map(|column| meta.query_advice(column.clone(), Rotation(36)))
                .collect_vec();

            let mut constraints: Vec<Expression<F>> = Vec::new();
            // check all entries of c are bits
            // check relation between c and c'
            for x in 0..5 {
                for z in 0..64 {
                    constraints.push(is_bit(&c[x][z]));
                    constraints.push(
                        xor3(&c[x][z], &c[(x + 4) % 5][z], &c[(x + 1) % 5][(z + 63) % 64])
                            - cp[x][z].clone(),
                    );
                }
            }
            // check a'[x,y,z] are all bits
            // a[x,y,z] == a'[x,y,z] xor c[x,z] xor c'[x,z]
            for x in 0..5 {
                for y in 0..5 {
                    for z in 0..64 {
                        constraints.push(is_bit(&ap[x][y][z]));
                    }
                    constraints.push(
                        A[x][y].clone()
                            - bits_to_num((0..64).map(|z| xor3(&ap[x][y][z], &c[x][z], &cp[x][z]))),
                    );
                }
            }
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

            // check entries of a''[0][0][0..64] are bits and it actually is the bit representation of A''[0][0]
            constraints.extend(app_00.iter().map(|bit| is_bit(bit)));
            constraints.push(bits_to_num(app_00.clone()) - App[0][0].clone());

            // verifying computation of A'''
            constraints.push(
                bits_to_num((0..64).map(|i| {
                    xor(&app_00[i], &Expression::Constant(F::from(((RC[round] >> i) & 1) as u64)))
                })) - Appp_00.clone(),
            );

            dbg!(constraints.len());
            constraints.into_iter().map(|expression| q.clone() * expression).collect_vec()
        })
    }

    pub fn keccak_f1600_round(
        &self,
        ctx: &mut Context<'_, F>,
        lanes: &[AssignedValue<F>],
        round: usize,
        mut row_offset: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert_eq!(lanes.len(), 25);
        let mut App = vec![vec![Value::unknown(); 5]; 5];
        let mut Appp_00 = Value::unknown();
        let mut c = [[Value::unknown(); 64]; 5];
        let mut cp = [[Value::unknown(); 64]; 5];
        let mut ap = [[[Value::unknown(); 64]; 5]; 5];
        let mut app_00 = [Value::unknown(); 64];

        self.q_rounds[round].enable(&mut ctx.region, row_offset)?;
        // only do actual keccak computation if values are not None
        if lanes.iter().all(|lane| value_to_option(lane.value()).is_some()) {
            let mut A = [[0; 5]; 5];
            for x in 0..5 {
                for y in 0..5 {
                    A[x][y] =
                        value_to_option(lanes[5 * x + y].value()).unwrap().get_lower_128() as u64;
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
        let mut output = Vec::with_capacity(25);
        output.push(ctx.assign_cell(
            Witness(Appp_00),
            self.values[50],
            &self.context_id,
            50,
            row_offset,
            ctx.current_phase(),
        )?);
        for x in 0..5 {
            for y in 0..5 {
                ctx.assign_cell(
                    Existing(&lanes[5 * x + y]),
                    self.values[5 * x + y],
                    &self.context_id,
                    5 * x + y,
                    row_offset,
                    ctx.current_phase(),
                )?;
            }
        }
        for (i, a) in App.into_iter().flatten().into_iter().enumerate() {
            let assigned = ctx.assign_cell(
                Witness(a),
                self.values[25 + i],
                &self.context_id,
                25 + i,
                row_offset,
                ctx.current_phase(),
            )?;
            if i != 0 {
                output.push(assigned);
            }
        }
        row_offset += 1;
        for c_row in c.into_iter() {
            self.assign_row_silent(ctx, c_row.into_iter().map(|v| Witness(v)), row_offset)?;
            row_offset += 1;
        }
        for ap_i in ap.into_iter() {
            for ap_ij in ap_i.into_iter() {
                self.assign_row_silent(ctx, ap_ij.into_iter().map(|v| Witness(v)), row_offset)?;
                row_offset += 1;
            }
        }
        for c_row in cp.into_iter() {
            self.assign_row_silent(ctx, c_row.into_iter().map(|v| Witness(v)), row_offset)?;
            row_offset += 1;
        }
        self.assign_row_silent(ctx, app_00.into_iter().map(|v| Witness(v)), row_offset)?;

        Ok(output)
    }

    pub fn assign_row_silent<'a, I>(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: I,
        row_offset: usize,
    ) -> Result<(), Error>
    where
        I: IntoIterator<Item = QuantumCell<'a, F>>,
    {
        for (i, input) in inputs.into_iter().enumerate() {
            ctx.assign_cell(
                input,
                self.values[i],
                &self.context_id,
                i,
                row_offset,
                ctx.current_phase(),
            )?;
        }
        Ok(())
    }

    pub fn assign_row<'a, I>(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: I,
        row_offset: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error>
    where
        I: IntoIterator<Item = QuantumCell<'a, F>>,
    {
        Ok(inputs
            .into_iter()
            .enumerate()
            .map(|(i, input)| {
                ctx.assign_cell(
                    input,
                    self.values[i],
                    &self.context_id,
                    i,
                    row_offset,
                    ctx.current_phase(),
                )
                .unwrap()
            })
            .collect_vec())
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

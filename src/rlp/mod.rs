use std::marker::PhantomData;
use halo2_ecc::{
    gates::{Context, RangeInstructions},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Challenge, Circuit, Column, ConstraintSystem, Error,
	    Expression, FirstPhase, Fixed, Instance, SecondPhase, Selector},
    poly::Rotation,
};

use eth_types::Field;

#[derive(Clone, Debug)]
pub struct RlcTrace<F: Field> {
    rlc_trace: Vec<AssignedCell<F, F>>,
    rlc_max_val: AssignedCell<F, F>,
    rlc_val: AssignedCell<F, F>,
    rlc_len: AssignedCell<F, F>,
    max_len: usize,
}

#[derive(Clone, Debug)]
pub struct RlcChip<F> {
    val: Column<Advice>,
    rlc: Column<Advice>,
    q_rlc: Selector,
    q_mul: Selector,
    gamma: Challenge,

    _marker: PhantomData<F>
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

impl<F: Field> RlcChip<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
	let q_rlc = meta.selector();
	let q_mul = meta.selector();
	let val = meta.advice_column();
	let rlc = meta.advice_column_in(SecondPhase);
	let [gamma] = [(); 1].map(|_| meta.challenge_usable_after(FirstPhase));

	meta.enable_equality(val);
	meta.enable_equality(rlc);
	
	meta.create_gate("RLC computation", |meta| {
	    let sel = meta.query_selector(q_rlc);
	    let val = meta.query_advice(val, Rotation::cur());
	    let rlc_curr = meta.query_advice(rlc, Rotation::cur());
	    let rlc_prev = meta.query_advice(rlc, Rotation::prev());
	    let [gamma] = [gamma].map(|challenge| meta.query_challenge(challenge));
	    
	    vec![sel * (rlc_prev * gamma + val - rlc_curr)]
	});

	meta.create_gate("RLC mul", |meta| {
	    let sel = meta.query_selector(q_mul);
	    let a = meta.query_advice(rlc, Rotation::cur());
	    let b = meta.query_advice(rlc, Rotation(1));
	    let c = meta.query_advice(rlc, Rotation(2));
	    let d = meta.query_advice(rlc, Rotation(3));

	    vec![sel * (a + b * c - d)]
	});

	let config = Self {
	    val,
	    rlc,
	    q_rlc,
	    q_mul,
	    gamma,
	    _marker: PhantomData
	};

	config
    }

    pub fn compute_rlc(
	&self,
	layouter: &mut impl Layouter<F>,
	ctx: &mut Context<F>,
	range: &impl RangeInstructions<F>,
	input: &[AssignedCell<F, F>],
	len: AssignedCell<F, F>,
	max_len: usize,
	rlc_cache: &[AssignedCell<F, F>],
    ) -> Result<RlcTrace<F>, Error> {
	assert!(input.len() == max_len);

	let gamma = layouter.get_challenge(self.gamma);
	let assigned = layouter.assign_region(
	    || "RLC array",
	    |mut region| {
		let mut rlc_cells = Vec::new();
		let mut running_rlc = Value::known(F::from(0));
		for (idx, val) in input.iter().enumerate() {
		    let val_assigned = val.copy_advice(
			|| "RLC input",
			&mut region,
			self.val,
			idx,
		    )?;

		    running_rlc = running_rlc * gamma + val.value();
		    let rlc_assigned = region.assign_advice(
			|| "RLC compute",
			self.rlc,
			idx,
			|| running_rlc
		    )?;
		    rlc_cells.push(rlc_assigned.clone());

		    if idx == 0 {
			region.constrain_equal(rlc_assigned.cell(), val_assigned.cell())?;
		    } else {
			self.q_rlc.enable(&mut region, idx)?;
		    }
		}
		Ok((rlc_cells.clone(), rlc_cells[max_len - 1].clone()))
	    }
	)?;
	let rlc_max_val = assigned.1;

	let pow_diff = layouter.assign_region(
	    || "RLC power diff",
	    |mut region| {
		// | len | 1 | diff | max_len |
		let len_assigned = len.copy_advice(
		    || "len copy",
		    &mut region,
		    self.rlc,
		    0
		)?;
		let one = region.assign_advice(
		    || "one",
		    self.rlc,
		    1,
		    || Value::known(F::from(1))
		)?;
		region.constrain_constant(one.cell(), F::from(1))?;
		let diff = region.assign_advice(
		    || "diff",
		    self.rlc,
		    2,
		    || len.value().map(|x| F::from(max_len as u64) - x)
		)?;
		let ml = region.assign_advice(
		    || "ml",
		    self.rlc,
		    3,
		    || Value::known(F::from(max_len as u64))
		)?;
		region.constrain_constant(ml.cell(), F::from(max_len as u64))?;
		self.q_mul.enable(&mut region, 0)?;
		Ok(diff)
	    }
	)?;
	
	let rlc_pow = self.rlc_pow(
	    layouter,
	    ctx,
	    range,
	    pow_diff,
	    log2(max_len + 1),
	    rlc_cache
	)?;

	let rlc_val = layouter.assign_region(
	    || "RLC pow diff check",
	    |mut region| {
		// | 0 | rlc_val | rlc_pow | rlc_max_val |
		let zero = region.assign_advice(
		    || "zero",
		    self.rlc,
		    0,
		    || Value::known(F::from(0))
		)?;
		region.constrain_constant(zero.cell(), F::from(0))?;
		let rlc_val = region.assign_advice(
		    || "rlc_val",
		    self.rlc,
		    1,
		    || rlc_max_val.value().zip(rlc_pow.value()).map(|(x, y)| (*x) * (*y).invert().unwrap())
		)?;
		let rlc_pow_copy = rlc_pow.copy_advice(
		    || "rlc_pow_copy",
		    &mut region,
		    self.rlc,
		    2
		)?;
		let rlc_max_val_copy = rlc_max_val.copy_advice(
		    || "rlc_max_val_copy",
		    &mut region,
		    self.rlc,
		    3
		)?;
		self.q_mul.enable(&mut region, 0)?;
		Ok(rlc_val)
	    }
	)?;
	
	let rlc_trace = RlcTrace {
	    rlc_trace: assigned.0,
	    rlc_max_val: rlc_max_val,
	    rlc_val: rlc_val,
	    rlc_len: len,
	    max_len: max_len,
	};
	Ok(rlc_trace)
    }

    pub fn load_rlc_cache(
	&self,
	layouter: &mut impl Layouter<F>,
	cache_bits: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
	let gamma = layouter.get_challenge(self.gamma);

	let cache = layouter.assign_region(
	    || "gamma cache",
	    |mut region| {
		let mut cache = Vec::new();
		for idx in 0..cache_bits {
		    if idx == 0 {
			let one = region.assign_advice(
			    || "one",
			    self.rlc,
			    0,
			    || Value::known(F::from(1))
			)?;
			region.constrain_constant(one.cell(), F::from(1))?;
			let zero = region.assign_advice(
			    || "zero",
			    self.val,
			    1,
			    || Value::known(F::from(0))
			)?;
			region.constrain_constant(zero.cell(), F::from(0))?;
			let cache0 = region.assign_advice(
			    || "gamma",
			    self.rlc,
			    1,
			    || gamma
			)?;
			self.q_rlc.enable(&mut region, 1)?;
			cache.push(cache0);
		    } else if idx == 1 {
			cache[0].copy_advice(
			    || "gamma",
			    &mut region,
			    self.rlc,
			    2,
			)?;
			let cache1 = region.assign_advice(
			    || "gamma^2",
			    self.rlc,
			    3,
			    || gamma * gamma
			)?;
			self.q_mul.enable(&mut region, 0)?;
			cache.push(cache1);
		    } else {
			let zero = region.assign_advice(
			    || "zero",
			    self.rlc,
			    4 * idx - 4,
			    || Value::known(F::from(0))
			)?;
			region.constrain_constant(zero.cell(), F::from(0))?;
			let next = cache[cache.len() - 1].copy_advice(
			    || "prev copy",
			    &mut region,
			    self.rlc,
			    4 * idx - 3
			)?;
			let next2 = cache[cache.len() - 1].copy_advice(
			    || "prev copy",
			    &mut region,
			    self.rlc,
			    4 * idx - 2
			)?;
			region.constrain_equal(next.cell(), cache[cache.len() - 1].cell())?;
			region.constrain_equal(next2.cell(), cache[cache.len() - 1].cell())?;
			let next3 = region.assign_advice(
			    || "gamma next",
			    self.rlc,
			    4 * idx - 1,
			    || cache[cache.len() - 1].value().map(|x| (*x) * (*x))
			)?;
			self.q_mul.enable(&mut region, 4 * idx - 4)?;
			cache.push(next3);
		    }
		}
		Ok(cache)
	    }
	)?;
	Ok(cache)
    }
    
    pub fn rlc_pow(
	&self,
	layouter: &mut impl Layouter<F>,
	ctx: &mut Context<F>,
	range: &impl RangeInstructions<F>,
	pow: AssignedCell<F, F>,
	pow_bits: usize,
	rlc_cache: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, Error> {
	assert!(pow_bits <= rlc_cache.len());
	
	let bits = range.num_to_bits(
	    ctx,
	    &pow,
	    pow_bits,
	)?;

	// multi-exp of bits and rlc_cache
	let dot = layouter.assign_region(
	    || "bit product",
	    |mut region| {
		let mut prod_cells = Vec::new();
		for idx in 0..pow_bits {
		    // prod = bit * x + (1 - bit)
		    // | 1 | bit | x | 1 + bit * x |
		    // | bit | prod | 1 | bit + prod |
		    let one = region.assign_advice(
			|| "one",
			self.rlc,
			8 * idx,
			|| Value::known(F::from(1))
		    )?;
		    region.constrain_constant(one.cell(), F::from(1))?;
		    let bit_copy = bits[idx].copy_advice(
			|| "bit_copy",
			&mut region,
			self.rlc,
			8 * idx + 1
		    )?;
		    let cache_copy = rlc_cache[idx].copy_advice(
			|| "cache_copy",
			&mut region,
			self.rlc,
			8 * idx + 2
		    )?;
		    let eq_check = region.assign_advice(
			|| "eq",
			self.rlc,
			8 * idx + 3,
			|| bits[idx].value().zip(rlc_cache[idx].value()).map(|(a, b)| F::from(1) + (*a) * (*b))
		    )?;
		    self.q_mul.enable(&mut region, 8 * idx)?;

		    let bit_copy2 = bits[idx].copy_advice(
			|| "bit_copy",
			&mut region,
			self.rlc,
			8 * idx + 4
		    )?;
		    let prod = region.assign_advice(
			|| "eq",
			self.rlc,
			8 * idx + 5,
			|| bits[idx].value().zip(rlc_cache[idx].value()).map(|(a, b)| F::from(1) + (*a) * (*b) - (*a))
		    )?;
		    let one2 = region.assign_advice(
			|| "one",
			self.rlc,
			8 * idx + 6,
			|| Value::known(F::from(1))
		    )?;
		    region.constrain_constant(one2.cell(), F::from(1))?;
		    eq_check.copy_advice(
			|| "eq2",
			&mut region,
			self.rlc,
			8 * idx + 7
		    )?;
		    self.q_mul.enable(&mut region, 8 * idx + 4)?;

		    prod_cells.push(prod);		    
		}

		let mut intermed = Vec::new();
		for idx in 0..(pow_bits - 1) {
		    if idx == 0 {
			let one = region.assign_advice(
			    || "one",
			    self.rlc,
			    8 * pow_bits,
			    || Value::known(F::from(1))
			)?;
			region.constrain_constant(one.cell(), F::from(1))?;
			prod_cells[0].copy_advice(
			    || "cache0",
			    &mut region,
			    self.rlc,
			    8 * pow_bits + 1
			)?;
			prod_cells[1].copy_advice(
			    || "cache1",
			    &mut region,
			    self.rlc,
			    8 * pow_bits + 2
			)?;
			let prod1 = region.assign_advice(
			    || "prod1",
			    self.rlc,
			    8 * pow_bits + 3,
			    || prod_cells[0].value().zip(prod_cells[1].value()).map(|(a, b)| (*a) * (*b))
			)?;
			self.q_mul.enable(&mut region, 8 * pow_bits)?;
			intermed.push(prod1);
		    } else {
			let one = region.assign_advice(
			    || "one",
			    self.rlc,
			    8 * pow_bits + 4 * idx,
			    || Value::known(F::from(1))
			)?;
			region.constrain_constant(one.cell(), F::from(1))?;
			prod_cells[idx + 1].copy_advice(
			    || "cache",
			    &mut region,
			    self.rlc,
			    8 * pow_bits + 4 * idx + 1,
			)?;
			intermed[intermed.len() - 1].copy_advice(
			    || "intermed",
			    &mut region,
			    self.rlc,
			    8 * pow_bits + 4 * idx + 2,
			)?;
			let prod = region.assign_advice(
			    || "prod",
			    self.rlc,
			    8 * pow_bits + 4 * idx + 3,
			    || prod_cells[idx + 1].value().zip(intermed[intermed.len() - 1].value()).map(|(a, b)| (*a) * (*b))
			)?;
			self.q_mul.enable(&mut region, 8 * pow_bits + 4 * idx)?;
			intermed.push(prod);			
		    }
		}
		Ok(intermed[intermed.len() - 1].clone())
	    }
	)?;
	
	Ok(dot)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    pub fn test_rlp_rlc() {
	
    }
}
